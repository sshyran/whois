package net.ripe.db.whois.update.keycert;

import net.ripe.db.whois.common.rpsl.RpslObject;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

// TODO: [ES] needs more tests (including negative tests)
// TODO:      generate signed messages on demand (don't hardcode RPSL data as it makes it hard to change later)
public class PgpCompressedSignedMessageTest {


    @Test
    public void verify_compressed_signed_message() {
        final PgpCompressedSignedMessage message = PgpCompressedSignedMessage.parse(
                "-----BEGIN PGP SIGNED MESSAGE-----\n" +
                "Hash: SHA256\n" +
                "\n" +
                "person: Test Person\n" +
                "address:München, Germany\n" +
                "phone:  +49 282 411141\n" +
                "fax-no: +49 282 411140\n" +
                "nic-hdl:TP1-TEST\n" +
                "mnt-by: UPD-MNT\n" +
                "source: INVALID\n" +
                "-----BEGIN PGP SIGNATURE-----\n" +
                "Comment: GPGTools - http://gpgtools.org\n" +
                "\n" +
                "owGbwMvMwMG4+8xu3fDkqbyMa2YncSfn55Wk5pXolVSUhIutMS9ILSrOz7NSCEkt\n" +
                "LlEIAHO4ElNSilKLi618/+QlZ6Tm6Si4pxblJuZVchVk5OelWikoaJtYKhhZGCmY\n" +
                "GBoamhhypSVW6OblW6EKG3DlZSbrZqTkWIUEGOqGuAaHKHDl5pXoJlVaKYQGuOj6\n" +
                "+oVwFeeXFiUDDQTJcnUyyrAwMHIwsLEygRzGwMUpAHN4uQP7/0Q/Pea798S3Mcba\n" +
                "b/BxTJZpFV7289/cOadTAl7+XPTm8Z02hQ9nd+44P8PXd9WDxw+e9Mc/rMv0nfTO\n" +
                "/MN21+vb3nxfa2/Afud/e2dqW8q1G8xn5YrL+rotk6bmsHh1TNokHWam9v2b6Laj\n" +
                "xluXKm77Y5z62OH03Muq195mRWvfuiT6ept18ERVkc+i+T59DkUTPDNPrBOuatHa\n" +
                "qvw+T0nfXVONt2z+E0HG2atuXYti6V9+0yPdR+JDu+O0NQ3nK+1uGbh+KVkj8tii\n" +
                "6mCp2dHHtvaTbn9a/PS1H/tG4+1bpRudJAN2vtdoWT1x2xzJ2QbPCs9P/eh07u/O\n" +
                "KZ8spzzldNtzN3vC+2dLfeatnWgPAA==\n" +
                "=Ug0S\n" +
                "-----END PGP SIGNATURE-----");

        assertThat(message.verify(getPublicKey_5763950D()), is(true));
    }

    private PGPPublicKey getPublicKey_5763950D() {
        PgpPublicKeyWrapper wrapper = PgpPublicKeyWrapper.parse(
                RpslObject.parse(
                        "key-cert:       PGPKEY-5763950D\n" +
                        "method:         PGP\n" +
                        "owner:          No Reply <noreply@ripe.net>\n" +
                        "fingerpr:       884F 8E23 69E5 E6F1 9FB3  63F4 BBCC BB2D 5763 950D\n" +
                        "certif:         -----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                        "certif:         Version: GnuPG v1.4.12 (Darwin)\n" +
                        "certif:\n" +
                        "certif:         mQENBFC0yvUBCACn2JKwa5e8Sj3QknEnD5ypvmzNWwYbDhLjmD06wuZxt7Wpgm4+\n" +
                        "certif:         yO68swuow09jsrh2DAl2nKQ7YaODEipis0d4H2i0mSswlsC7xbmpx3dRP/yOu4WH\n" +
                        "certif:         2kZciQYxC1NY9J3CNIZxgw6zcghJhtm+LT7OzPS8s3qp+w5nj+vKY09A+BK8yHBN\n" +
                        "certif:         E+VPeLOAi+D97s+Da/UZWkZxFJHdV+cAzQ05ARqXKXeadfFdbkx0Eq2R0RZm9R+L\n" +
                        "certif:         A9tPUhtw5wk1gFMsN7c5NKwTUQ/0HTTgA5eyKMnTKAdwhIY5/VDxUd1YprnK+Ebd\n" +
                        "certif:         YNZh+L39kqoUL6lqeu0dUzYp2Ll7R2IURaXNABEBAAG0I25vcmVwbHlAcmlwZS5u\n" +
                        "certif:         ZXQgPG5vcmVwbHlAcmlwZS5uZXQ+iQE4BBMBAgAiBQJQtMr1AhsDBgsJCAcDAgYV\n" +
                        "certif:         CAIJCgsEFgIDAQIeAQIXgAAKCRC7zLstV2OVDdjSCACYAyyWr83Df/zzOWGP+qMF\n" +
                        "certif:         Vukj8xhaM5f5MGb9FjMKClo6ezT4hLjQ8hfxAAZxndwAXoz46RbDUsAe/aBwdwKB\n" +
                        "certif:         0owcacoaxUd0i+gVEn7CBHPVUfNIuNemcrf1N7aqBkpBLf+NINZ2+3c3t14k1BGe\n" +
                        "certif:         xCInxEqHnq4zbUmunCNYjHoKbUj6Aq7janyC7W1MIIAcOY9/PvWQyf3VnERQImgt\n" +
                        "certif:         0fhiekCr6tRbANJ4qFoJQSM/ACoVkpDvb5PHZuZXf/v+XB1DV7gZHjJeZA+Jto5Z\n" +
                        "certif:         xrmS5E+HEHVBO8RsBOWDlmWCcZ4k9olxp7/z++mADXPprmLaK8vjQmiC2q/KOTVA\n" +
                        "certif:         uQENBFC0yvUBCADTYI6i4baHAkeY2lR2rebpTu1nRHbIET20II8/ZmZDK8E2Lwyv\n" +
                        "certif:         eWold6pAWDq9E23J9xAWL4QUQRQ4V+28+lknMySXbU3uFLXGAs6W9PrZXGcmy/12\n" +
                        "certif:         pZ+82hHckh+jN9xUTtF89NK/wHh09SAxDa/ST/z/Dj0k3pQWzgBdi36jwEFtHhck\n" +
                        "certif:         xFwGst5Cv8SLvA9/DaP75m9VDJsmsSwh/6JqMUb+hY71Dr7oxlIFLdsREsFVzVec\n" +
                        "certif:         YHsKINlZKh60dA/Br+CC7fClBycEsR4Z7akw9cPLWIGnjvw2+nq9miE005QLqRy4\n" +
                        "certif:         dsrwydbMGplaE/mZc0d2WnNyiCBXAHB5UhmZABEBAAGJAR8EGAECAAkFAlC0yvUC\n" +
                        "certif:         GwwACgkQu8y7LVdjlQ1GMAgAgUohj4q3mAJPR6d5pJ8Ig5E3QK87z3lIpgxHbYR4\n" +
                        "certif:         HNaR0NIV/GAt/uca11DtIdj3kBAj69QSPqNVRqaZja3NyhNWQM4OPDWKIUZfolF3\n" +
                        "certif:         eY2q58kEhxhz3JKJt4z45TnFY2GFGqYwFPQ94z1S9FOJCifL/dLpwPBSKucCac9y\n" +
                        "certif:         6KiKfjEehZ4VqmtM/SvN23GiI/OOdlHL/xnU4NgZ90GHmmQFfdUiX36jWK99LBqC\n" +
                        "certif:         RNW8V2MV+rElPVRHev+nw7vgCM0ewXZwQB/bBLbBrayx8LzGtMvAo4kDJ1kpQpip\n" +
                        "certif:         a/bmKCK6E+Z9aph5uoke8bKoybIoQ2K3OQ4Mh8yiI+AjiQ==\n" +
                        "certif:         =HQmg\n" +
                        "certif:         -----END PGP PUBLIC KEY BLOCK-----\n" +
                        "notify:         noreply@ripe.net\n" +
                        "mnt-by:         ADMIN-MNT\n" +
                        "source:         TEST"));

        return wrapper.getPublicKey();
    }


}