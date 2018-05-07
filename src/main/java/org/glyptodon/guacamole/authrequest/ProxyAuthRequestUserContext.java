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

import java.util.Collections;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.simple.SimpleUserContext;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.glyptodon.guacamole.authrequest.token.TokenGenerator;

/**
 * UserContext implementation which automatically associates and maintains a
 * unique token with an authenticated user of Guacamole. The generated token is
 * guaranteed to be sufficiently random, sufficiently long, and unique across
 * all users. The token will automatically be revoked once the user logs out of
 * Guacamole.
 */
public class ProxyAuthRequestUserContext extends SimpleUserContext {

    /**
     * The {@link TokenGenerator} to use to generate the token for the user
     * associated with this UserContext.
     */
    private final TokenGenerator tokens;

    /**
     * The unique token assigned to the user that authenticated.
     */
    private final String token;

    /**
     * Creates a new ProxyAuthRequestUserContext associated with the given
     * AuthenticationProvider which maintains a unique token for the given
     * AuthenticatedUser.
     *
     * @param authProvider
     *     A reference to the ProxyAuthRequestAuthenticationProvider instance
     *     that created this ProxyAuthRequestUserContext.
     *
     * @param authenticatedUser
     *     The user that successfully authenticated.
     *
     * @param tokens
     *     The {@link TokenGenerator} to use to generate a unique token for the
     *     user that successfully authenticated, and to revoke that token once
     *     the user logs out.
     */
    public ProxyAuthRequestUserContext(AuthenticationProvider authProvider,
            AuthenticatedUser authenticatedUser, TokenGenerator tokens) {
        super(authProvider, authenticatedUser.getIdentifier(), Collections.<String, GuacamoleConfiguration>emptyMap());
        this.tokens = tokens;
        this.token = tokens.generateToken();
    }

    /**
     * Returns the unique token assigned to the user associated with this
     * UserContext. This token is guaranteed to be sufficiently random,
     * sufficiently long, and unique across all users. The token will
     * automatically be revoked once the user logs out of Guacamole.
     *
     * @return
     *     The unique token assigned to the user associated with this
     *     UserContext.
     */
    public String getToken() {
        return token;
    }

    @Override
    public void invalidate() {
        tokens.revokeToken(token);
        super.invalidate();
    }

}
