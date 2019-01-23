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

package org.glyptodon.guacamole.authrequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;
import org.glyptodon.guacamole.authrequest.rest.AuthStatusResource;
import org.glyptodon.guacamole.authrequest.token.TokenGenerator;

/**
 * AuthenticationProvider implementation which assigns a unique token to each
 * user that successfully authenticates. This unique token is stored within the
 * HttpSession such that the presence of a valid Guacamole session can be
 * determined through an HTTP request to a specific REST endpoint.
 */
public class ProxyAuthRequestAuthenticationProvider extends AbstractAuthenticationProvider {

    /**
     * The {@link TokenGenerator} to use to generate tokens for authenticated
     * users and to validate those tokens.
     */
    private final TokenGenerator tokens = new TokenGenerator();

    @Override
    public String getIdentifier() {
        return "proxy-authrequest";
    }

    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser)
            throws GuacamoleException {

        // Pull servlet request, aborting early if the request does not actually
        // exist
        Credentials credentials = authenticatedUser.getCredentials();
        HttpServletRequest request = credentials.getRequest();
        if (request == null)
            return null;

        // Create a user context with an associated unique token
        ProxyAuthRequestUserContext context =
                new ProxyAuthRequestUserContext(this, authenticatedUser, tokens);

        // Store the unique token within the HttpSession
        HttpSession session = request.getSession(true);
        session.setAttribute(AuthStatusResource.TOKEN_ATTRIBUTE,
                context.getToken());

        return context;

    }

    @Override
    public Object getResource() throws GuacamoleException {
        return new AuthStatusResource(tokens);
    }

}
