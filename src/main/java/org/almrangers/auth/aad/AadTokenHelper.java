/**
 * Azure Active Directory Authentication Plugin for SonarQube
 * <p>
 * Copyright (c) 2022 Michael Johnson
 * <p>
 * The MIT License (MIT)
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package org.almrangers.auth.aad;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import org.sonar.api.server.authentication.UnauthorizedException;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;

public class AadTokenHelper {

    private static final Logger LOGGER = Loggers.get(AadTokenHelper.class);

    AadTokenHelper() {
        throw new IllegalStateException("This is a utility class, do not instantiate it.");
    }

    public static boolean validateIdToken(JWT idToken, AadSettings settings) throws MalformedURLException, BadJOSEException, JOSEException {

        // Create a JWT processor for the access tokens
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor =
            new DefaultJWTProcessor<>();

        JWKSource<SecurityContext> keySource =
            new RemoteJWKSet<>(new URL(settings.jwkKeysUrl()));

        //MS uses RSA 256 to sign their JWTs
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        JWSKeySelector<SecurityContext> keySelector =
            new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);

        jwtProcessor.setJWSKeySelector(keySelector);

        // Verify the specific claims in the ID token. Confirm the audience matches
        // the expected value (our Client ID), and that specific attributes are present.
        // Note that this also automatically validates the various timestamp values
        // to ensure the token is still valid.
        jwtProcessor.setJWTClaimsSetVerifier(
            new DefaultJWTClaimsVerifier<>(
                settings.clientId().orElse(null),
                null,
                new HashSet<>(Arrays.asList("iss", "iat", "nbf", "exp", "oid", "name", "preferred_username", "sub", "tid"))
            )
        );

        // Don't capture the output. This will throw an error if the token doesn't
        // validate instead of returning true.
        jwtProcessor.process(idToken, null);

        return true; // If there was no exception thrown, then the token is valid
    }

    public static OIDCTokenResponse extractTokenResponse(HTTPResponse tokenHTTPResp) {
        OIDCTokenResponse tokenResponse;

        try {
            //If we got an error in the token process, this will catch it and log the details.
            if(!tokenHTTPResp.indicatesSuccess()) {
                TokenErrorResponse tokenErrorResponse = TokenResponse.parse(tokenHTTPResp).toErrorResponse();

                LOGGER.error("Issue getting authentication token. Returned error: "
                    + tokenErrorResponse.getErrorObject().getDescription());
            }

            tokenResponse = OIDCTokenResponse.parse(tokenHTTPResp);

        } catch (ParseException e) {
            throw new UnauthorizedException("Error when authenticating user. Please check the logs for more details.");
        }

        return tokenResponse;
    }
}
