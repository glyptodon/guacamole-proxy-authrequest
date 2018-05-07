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

package org.glyptodon.guacamole.authrequest.token;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.xml.bind.DatatypeConverter;

/**
 * Generates and tracks the validity of unique tokens.
 */
public class TokenGenerator {

    /**
     * The size of each generated token, in bytes. The value 18 has been chosen
     * here as it is a multiple of 3 and has at least 128 bits. Lengths which
     * are multiples of 3 will cleanly encode as base64 without need for
     * padding.
     */
    private static final int TOKEN_SIZE = 18;

    /**
     * The set of all valid tokens.
     */
    private final Set<String> tokens = Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());

    /**
     * The secure random number generator to use to generate tokens.
     */
    private final SecureRandom random = new SecureRandom();

    /**
     * Generates a new, unique token of reasonable length. The resulting token
     * is guaranteed to be sufficiently random and not have been generated
     * before. Future calls to {@link #isValid()} will return true until the
     * token is revoked through a call to {@link #revokeToken()}.
     *
     * @return
     *     A new, unique token.
     */
    public String generateToken() {

        // Pull random bytes for token
        byte[] tokenBytes = new byte[TOKEN_SIZE];
        random.nextBytes(tokenBytes);

        // Add string version of token to internal set of tokens
        String token = DatatypeConverter.printBase64Binary(tokenBytes);
        tokens.add(token);

        return token;

    }

    /**
     * Revokes the given token such that future calls to {@link #isValid()}
     * with that token will return false. If the token is invalid or has
     * already been revoked, this function has no effect.
     *
     * @param token
     *     The token to revoke.
     */
    public void revokeToken(String token) {
        tokens.remove(token);
    }

    /**
     * Returns whether the given token is valid. A token is valid if it was
     * returned from a call to {@link #generateToken()} and has not yet been
     * revoked through a call to {@link #revokeToken()}.
     *
     * @param token
     *     The token to test.
     *
     * @return
     *     true if the token is valid, false otherwise.
     */
    public boolean isValid(String token) {
        return tokens.contains(token);
    }

}
