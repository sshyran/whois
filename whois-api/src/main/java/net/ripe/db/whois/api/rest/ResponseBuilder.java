package net.ripe.db.whois.api.rest;

import javax.ws.rs.core.Response;

public abstract class ResponseBuilder {

    public static Response badRequest(final String message) {
        return Response.status(Response.Status.BAD_REQUEST).entity(message).build();
    }
}
