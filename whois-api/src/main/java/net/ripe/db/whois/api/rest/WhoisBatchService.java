package net.ripe.db.whois.api.rest;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import net.ripe.db.whois.api.rest.domain.Action;
import net.ripe.db.whois.api.rest.domain.ActionRequest;
import net.ripe.db.whois.api.rest.domain.Attribute;
import net.ripe.db.whois.api.rest.domain.WhoisObject;
import net.ripe.db.whois.api.rest.domain.WhoisResources;
import net.ripe.db.whois.api.rest.enums.SsoAuthType;
import net.ripe.db.whois.api.rest.mapper.FormattedServerAttributeMapper;
import net.ripe.db.whois.api.rest.mapper.WhoisObjectMapper;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.rpsl.RpslObjectBuilder;
import net.ripe.db.whois.common.source.SourceContext;
import org.eclipse.jetty.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.Consumes;
import javax.ws.rs.CookieParam;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static net.ripe.db.whois.api.rest.ResponseBuilder.badRequest;

@Component
@Path("/batch")
public class WhoisBatchService {

    private static final Logger LOGGER = LoggerFactory.getLogger(WhoisBatchService.class);

    private final SourceContext sourceContext;
    private final WhoisService whoisService;
    private final InternalUpdatePerformer updatePerformer;
    private final WhoisObjectMapper whoisObjectMapper;
    private final String dummyRole;

    @Autowired
    public WhoisBatchService(
        final SourceContext sourceContext,
        final WhoisService whoisService,
        final WhoisObjectMapper whoisObjectMapper,
        final InternalUpdatePerformer updatePerformer,
        @Value("${whois.dummy_role.nichdl}") final String dummyRole) {

        this.sourceContext = sourceContext;
        this.whoisService = whoisService;
        this.updatePerformer = updatePerformer;
        this.whoisObjectMapper = whoisObjectMapper;
        this.dummyRole = dummyRole;
    }

    //TODO [TP]: This method has to go to its own class and path.
    /**
     * Update one or more objects together (in the same transaction). If any update fails, then all changes are cancelled (rolled back).
     *
     * If any update fails, the response will contain all (attempted) changes up to, and including, that update.
     * Any error message will refer to the last attempted update.
     *
     */
    @PUT
    @Consumes({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    @Path("/{source}")
    public Response update(
            final WhoisResources resource,
            @PathParam("source") final String sourceParam,
            @Context final HttpServletRequest request,
            @QueryParam("override") final String override) {

        if (resource == null) {
            return badRequest("WhoisResources is mandatory");
        }

        if (Strings.isNullOrEmpty(override)) {
            return badRequest("override is mandatory");
        }

        checkForMainSource(request, sourceParam);

        try {
            final WhoisResources updatedResources = updatePerformer.performUpdates(request, convertToActionRequests(resource), Collections.<String>emptyList(), "", override, SsoAuthType.ACCOUNT);
            return createResponse(request, updatedResources, Response.Status.OK);

        } catch (WebApplicationException e) {
            final Response response = e.getResponse();

            switch (response.getStatus()) {
                case HttpStatus.UNAUTHORIZED_401:
                    throw new NotAuthorizedException(createResponse(request, resource, Response.Status.UNAUTHORIZED));

                case HttpStatus.INTERNAL_SERVER_ERROR_500:
                    throw new InternalServerErrorException(createResponse(request, resource, Response.Status.INTERNAL_SERVER_ERROR));

                default:
                    throw new BadRequestException(createResponse(request, resource, Response.Status.BAD_REQUEST));
            }

        } catch (UpdateFailedException e) {
            return createResponse(request, e.whoisResources, e.status);
        }
        catch (Exception e) {
            LOGGER.error("Unexpected", e);
            return createResponse(request, resource, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @POST
    @Consumes({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    @Path("/{source}")
    public Response create(
            final WhoisResources resource,
            @PathParam("source") final String sourceParam,
            @Context final HttpServletRequest request,
            @QueryParam("password") final List<String> passwords,
            @CookieParam("crowd.token_key") final String crowdTokenKey) {

        if (resource == null) {
            return badRequest("WhoisResources is mandatory");
        }

        checkForMainSource(request, sourceParam);

        try {
            final List<ActionRequest> actionRequests = Lists.newArrayList();

            final RpslObject mntner = createMntnerWithDummyAdminC(resource);
            actionRequests.add(new ActionRequest(mntner, Action.CREATE));

            final RpslObject person = createPerson(resource);
            actionRequests.add(new ActionRequest(person, Action.CREATE));

            final RpslObject updatedMntner = replaceAdminC(mntner, "AUTO-1");
            actionRequests.add(new ActionRequest(updatedMntner, Action.MODIFY));

            final WhoisResources whoisResources = updatePerformer.performUpdates(request, actionRequests, passwords, crowdTokenKey, null, SsoAuthType.ACCOUNT);
            return createResponse(request, filterWhoisObjects(whoisResources), Response.Status.OK);

        } catch (WebApplicationException e) {
            final Response response = e.getResponse();

            switch (response.getStatus()) {
                case HttpStatus.UNAUTHORIZED_401:
                    throw new NotAuthorizedException(createResponse(request, resource, Response.Status.UNAUTHORIZED));

                case HttpStatus.INTERNAL_SERVER_ERROR_500:
                    throw new InternalServerErrorException(createResponse(request, resource, Response.Status.INTERNAL_SERVER_ERROR));

                default:
                    throw new BadRequestException(createResponse(request, resource, Response.Status.BAD_REQUEST));
            }

        } catch (UpdateFailedException e) {
            return createResponse(request, e.whoisResources, e.status);
        }
        catch (Exception e) {
            LOGGER.error("Unexpected", e);
            return createResponse(request, resource, Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    private class UpdateFailedException extends RuntimeException {
        private final WhoisResources whoisResources;
        private final Response.Status status;

        public UpdateFailedException(Response.Status status, WhoisResources whoisResources) {
            this.status = status;
            this.whoisResources = whoisResources;
        }
    }

    // return only the last version of each object
    private WhoisResources filterWhoisObjects(final WhoisResources whoisResources) {
        final Map<List<Attribute>, WhoisObject> result = Maps.newHashMap();

        for (WhoisObject whoisObject : whoisResources.getWhoisObjects()) {
            result.put(whoisObject.getPrimaryKey(), whoisObject);
        }

        whoisResources.setWhoisObjects(Lists.newArrayList(result.values()));
        return whoisResources;
    }

    private RpslObject replaceAdminC(final RpslObject mntnerObject, final String adminC) {
        final RpslObjectBuilder builder = new RpslObjectBuilder(mntnerObject);
        builder.replaceAttribute(mntnerObject.findAttribute(AttributeType.ADMIN_C), new RpslAttribute(AttributeType.ADMIN_C, adminC));
        return builder.get();
    }

    private RpslObject convertToRpslObject(final WhoisResources whoisResources, final ObjectType objectType) {
        for(WhoisObject whoisObject: whoisResources.getWhoisObjects()) {
            if (objectType == ObjectType.getByName(whoisObject.getType())) {
                return whoisObjectMapper.map(whoisObject, FormattedServerAttributeMapper.class);
            }
        }
        throw new IllegalArgumentException("Unable to find " + objectType + " in WhoisResources");
    }

    private RpslObject createPerson(final WhoisResources resource) {
        return convertToRpslObject(resource, ObjectType.PERSON);
    }

    private RpslObject createMntnerWithDummyAdminC(final WhoisResources resource) {
        final RpslObject mntnerObject = convertToRpslObject(resource, ObjectType.MNTNER);
        return replaceAdminC(mntnerObject, dummyRole);
    }


    private void checkForMainSource(final HttpServletRequest request, final String source) {
        if (!sourceContext.getCurrentSource().getName().toString().equalsIgnoreCase(source)) {
            throwBadRequest(request, RestMessages.invalidSource(source));
        }
    }

    private void throwBadRequest(final HttpServletRequest request, final Message message) {
        throw new WebApplicationException(Response.status(Response.Status.BAD_REQUEST)
                .entity(whoisService.createErrorEntity(request, message))
                .build());
    }

    private Response createResponse(final HttpServletRequest request, final WhoisResources whoisResources, final Response.Status status) {
        final Response.ResponseBuilder responseBuilder = Response.status(status);
        return responseBuilder.entity((StreamingOutput) output ->
                StreamingHelper.getStreamingMarshal(request, output).singleton(whoisResources)).build();
    }

    private List<ActionRequest> convertToActionRequests(final WhoisResources whoisResources) {
        final List<ActionRequest> actionRequests = Lists.newArrayList();

        for (WhoisObject whoisObject : whoisResources.getWhoisObjects()) {
            final RpslObject rpslObject = whoisObjectMapper.map(whoisObject, FormattedServerAttributeMapper.class);
            final Action action = whoisObject.getAction() != null ? whoisObject.getAction() : Action.MODIFY;
            actionRequests.add(new ActionRequest(rpslObject, action));
        }
        return actionRequests;
    }
}