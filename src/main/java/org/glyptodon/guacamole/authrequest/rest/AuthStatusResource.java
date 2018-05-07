/*
 * Copyright (C) 2018 Glyptodon, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.glyptodon.guacamole.authrequest.rest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.GET;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.glyptodon.guacamole.authrequest.token.TokenGenerator;

/**
 * A REST resource which tests the validity of tokens set within the
 * HttpSession during the authentication process of this extension.
 */
@Produces(MediaType.APPLICATION_JSON)
public class AuthStatusResource {

    /**
     * The attribute within the HttpSession which will store the token.
     */
    public static final String TOKEN_ATTRIBUTE = "GUAC_PROXY_AUTHREQUEST_TOKEN";

    /**
     * The {@link TokenGenerator} instance that will be used to generate the
     * tokens being tested.
     */
    private final TokenGenerator tokens;

    /**
     * Creates a new AuthStatusResource which validates the tokens stored
     * within the HttpSessions of requests against the given
     * {@link TokenGenerator}.
     *
     * @param tokens
     *     The {@link TokenGenerator} instance that will be used to generate
     *     the tokens that this resource will test.
     */
    public AuthStatusResource(TokenGenerator tokens) {
        this.tokens = tokens;
    }

    /**
     * Verifies whether the given request is associated with an existing
     * HttpSession that contains a valid token. An HttpSession will contain
     * such a valid token if and only if the associated request was made by
     * a user that is currently authenticated within this instance of
     * Guacamole.
     *
     * @param request
     *     The HTTP request to test.
     *
     * @return
     *     A successful (HTTP 200) response containing the JSON value true if
     *     the request contains a valid token, an unsuccessful (HTTP 403)
     *     response containing the JSON value false otherwise.
     */
    @GET
    public Response verifyStatus(@Context HttpServletRequest request) {

        // Verify session exists
        HttpSession session = request.getSession(false);
        if (session != null) {

            // Verify the token within the session corresponds to a user that
            // authenticated via Guacamole
            String token = (String) session.getAttribute(TOKEN_ATTRIBUTE);
            if (token != null && tokens.isValid(token))
                return Response.ok(Boolean.TRUE).build();

        }

        // The user has not authenticated or their session has expired
        return Response.status(Response.Status.FORBIDDEN)
                .entity(Boolean.FALSE).build();

    }

}
