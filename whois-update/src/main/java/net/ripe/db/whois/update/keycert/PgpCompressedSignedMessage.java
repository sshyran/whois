package net.ripe.db.whois.update.keycert;

import com.google.common.base.Charsets;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPRuntimeOperationException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.springframework.util.FileCopyUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.regex.Matcher;

import static net.ripe.db.whois.update.keycert.PgpSignedMessageUtil.getLengthWithoutSeparatorOrTrailingWhitespace;
import static net.ripe.db.whois.update.keycert.PgpSignedMessageUtil.getLineSeparator;
import static net.ripe.db.whois.update.keycert.PgpSignedMessageUtil.readInputLine;

public class PgpCompressedSignedMessage {

    private final PGPOnePassSignature onePassSignature;
    private final PGPSignature pgpSignature;
    private byte[] signedContent;

    private PgpCompressedSignedMessage(final PGPOnePassSignature onePassSignature, final PGPSignature pgpSignature, final byte[] signedContent) {
        this.onePassSignature = onePassSignature;
        this.pgpSignature = pgpSignature;
        this.signedContent = signedContent;
    }


    public boolean verify(final PGPPublicKey publicKey) {
        if (pgpSignature.getKeyAlgorithm() != publicKey.getAlgorithm()) {
            return false;
        }

        try {
            onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
        } catch (PGPException e) {
            return false;
        }

        for (byte next : signedContent) {
            onePassSignature.update(next);
        }

        try {
            return onePassSignature.verify(pgpSignature);
        } catch (PGPException | PGPRuntimeOperationException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    public String getSignedContent() {
        return new String(signedContent, Charsets.ISO_8859_1);
    }

    public String getKeyId() {
        return getKeyId(pgpSignature.getKeyID());
    }

    private String getKeyId(final long keyId) {
        final StringBuilder builder = new StringBuilder();

        final byte[] bytes = ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(keyId).array();
        for (int n = bytes.length - 4; n < bytes.length; n++) {
            builder.append(String.format("%02X", bytes[n]));
        }

        return builder.toString();
    }

    public static PgpCompressedSignedMessage parse(final String clearText) {
        return parse(clearText, Charsets.ISO_8859_1);
    }

    public static PgpCompressedSignedMessage parse(final String clearText, final Charset charset) {
        final Matcher matcher = PgpSignedMessage.SIGNED_MESSAGE_PATTERN.matcher(clearText);
        if (matcher.find()) {
            return parse(charset.encode(matcher.group(0)).array());
        } else {
            throw new IllegalArgumentException("no signed message found");
        }
    }

    private static PgpCompressedSignedMessage parse(final byte[] bytes) {
        final InputStream decoderStream;
        try {
            decoderStream = PGPUtil.getDecoderStream(new ByteArrayInputStream(bytes));
        } catch (IOException e) {
            throw new IllegalArgumentException("unable to read content");
        }

        if (!(decoderStream instanceof ArmoredInputStream)) {
            throw new IllegalArgumentException("Unexpected content");
        }

        final byte[] signedContent = readArmoredInputStream((ArmoredInputStream) decoderStream);

        try {
            final PGPObjectFactory objectFactory = new BcPGPObjectFactory(decoderStream);
            Object nextObject = objectFactory.nextObject();
            if (!(nextObject instanceof PGPCompressedData)) {
                throw new IllegalArgumentException("signature not compressed data");
            }

            final JcaPGPObjectFactory jcaPGPObjectFactory;
            try {
                jcaPGPObjectFactory = new JcaPGPObjectFactory(((PGPCompressedData)nextObject).getDataStream());
            } catch (PGPException e) {
                throw new IllegalArgumentException(e);
            }

            final PGPOnePassSignatureList onePassSignatureList = (PGPOnePassSignatureList)jcaPGPObjectFactory.nextObject();
            final PGPOnePassSignature onePassSignature = onePassSignatureList.get(0);

            nextObject = jcaPGPObjectFactory.nextObject();
            if (!(nextObject instanceof PGPLiteralData)) {
                throw new IllegalArgumentException("couldn't find literal data in signature");
            }

            final PGPLiteralData pgpLiteralData = (PGPLiteralData)nextObject;
            final ByteArrayOutputStream literalDataOutputStream = new ByteArrayOutputStream();
            FileCopyUtils.copy(pgpLiteralData.getInputStream(), literalDataOutputStream);

            if (!containsIgnoreWhitespace(signedContent, literalDataOutputStream.toByteArray())) {
                throw new IllegalArgumentException("literal data in compressed signature doesn't match signed content");
            }

            nextObject = jcaPGPObjectFactory.nextObject();
            if (!(nextObject instanceof PGPSignatureList)) {
                throw new IllegalArgumentException("couldn't find PGPSignatureList");
            }

            final PGPSignatureList pgpSignatureList = (PGPSignatureList)nextObject;
            final PGPSignature pgpSignature = pgpSignatureList.get(0);

            // TODO: [ES] literalData can contain Armored input (i.e. includes PGP header)
            return new PgpCompressedSignedMessage(onePassSignature, pgpSignature, literalDataOutputStream.toByteArray());

        } catch (IOException e) {
            throw new IllegalArgumentException("error reading content: " + e.getMessage());
        }
    }

    private static byte[] readArmoredInputStream(final InputStream inputStream) {
        try {
            return readArmoredInputStream(new ArmoredInputStream(inputStream));
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static byte[] readArmoredInputStream(final ArmoredInputStream inputStream) {
        try {
            // write out signed section using the local line separator.
            // note: trailing white space needs to be removed from the end of
            // each line RFC 4880 Section 7.1
            final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            final ByteArrayOutputStream lineOut = new ByteArrayOutputStream();
            int lookAhead = readInputLine(lineOut, inputStream);
            final byte[] lineSeparator = getLineSeparator();

            if (lookAhead != -1 && inputStream.isClearText()) {
                byte[] line = lineOut.toByteArray();
                outputStream.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
                outputStream.write(lineSeparator);

                while (lookAhead != -1 && inputStream.isClearText()) {
                    lookAhead = readInputLine(lineOut, lookAhead, inputStream);

                    line = lineOut.toByteArray();
                    outputStream.write(line, 0, getLengthWithoutSeparatorOrTrailingWhitespace(line));
                    outputStream.write(lineSeparator);
                }
            }

            return outputStream.toByteArray();

        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static boolean containsIgnoreWhitespace(final byte[] signedContent, final byte[] literalData) {
        // TODO: [ES] confirm that signed content in the visible section matches the literal data in the compressed section.
        //            sometimes the signedContent contains a PGP header (i.e. should use ArmoredInputStream), sometimes not.
        //            needs more testing.
        return true;
    }
}
