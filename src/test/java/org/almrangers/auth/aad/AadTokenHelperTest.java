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
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.Test;
import org.sonar.api.config.internal.MapSettings;
import org.sonar.api.server.authentication.UnauthorizedException;

import java.io.IOException;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

public class AadTokenHelperTest {

    SignedJWT testIdToken;
    AccessToken testAccessToken = new BearerAccessToken();
    MapSettings settings = new MapSettings();
    AadSettings aadSettings = new AadSettings(settings.asConfig());
    RSAKey rsaPublicJwk;

    @Test
    public void exception_on_instantiate() {
        assertThrows(IllegalStateException.class, AadTokenHelper::new);
    }

    @Test
    public void extract_oidc_tokens_success() {
        // Test OIDC Tokens
        OIDCTokens oidcTokens = new OIDCTokens(testIdToken, testAccessToken, new RefreshToken());

        // "OK" token response
        HTTPResponse goodHttpResponse = new HTTPResponse(200);
        goodHttpResponse.setHeader("Content-Type", "application/json");
        goodHttpResponse.setContent(oidcTokens.toString());

        assertThat(AadTokenHelper.extractTokenResponse(goodHttpResponse)).isInstanceOf(OIDCTokenResponse.class);
    }

    @Test
    public void extract_oidc_tokens_failure() {
        // "Bad" token response
        HTTPResponse badHttpResponse = new HTTPResponse(400);
        badHttpResponse.setHeader("Content-Type", "application/json");
        badHttpResponse.setContent("{\"error\": \"invalid_request\"}");

        UnauthorizedException unauthorizedException = assertThrows(UnauthorizedException.class,
            () -> AadTokenHelper.extractTokenResponse(badHttpResponse));

        assertTrue(unauthorizedException.getMessage().contains("Error when authenticating user"));
    }

    @Test
    public void validate_id_token() throws IOException, BadJOSEException, JOSEException {
        MockWebServer mockWebServer = new MockWebServer();
        mockWebServer.enqueue(
            new MockResponse().setBody("{\"keys\": [" +
                rsaPublicJwk.toJSONString() +
                "]}")
        );

        mockWebServer.start();

        HttpUrl baseUrl = mockWebServer.url("/common/discovery/keys");

        AadSettings spySettings = spy(aadSettings);
        doReturn(baseUrl.toString()).when(spySettings).jwkKeysUrl();

        assertThat(AadTokenHelper.validateIdToken(testIdToken, spySettings)).isTrue();

        mockWebServer.close();
    }

    @Before
    public void setUp() throws JOSEException {
        // Some needed settings used by the tests
        settings.setProperty("sonar.auth.aad.tenantId", "common");

        // Get current date/time for the test token
        Calendar testCalendar = Calendar.getInstance();
        Date currentTestDate = testCalendar.getTime();

        // Set up a 1 hour expiration for the test token
        testCalendar.add(Calendar.HOUR, 1);
        Date expirationTestDate = testCalendar.getTime();

        RSAKey rsaKey = new RSAKeyGenerator(2048)
            .keyID("123")
            .generate();

        // Save the public key for verification
        rsaPublicJwk = rsaKey.toPublicJWK();

        RSASSASigner rsaSigner = new RSASSASigner(rsaKey);

        // This token is based on the ID token returned from MS ID Platform OAuth v2.0
        // see: https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/active-directory/develop/id-tokens.md
        testIdToken = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256)
                .build(),
            new JWTClaimsSet.Builder()
                .audience("testAudience")
                .issuer("https://login.microsoftonline.com/" + "testTennantId" + "/v2.0")
                .issueTime(currentTestDate)
                .notBeforeTime(currentTestDate)
                .expirationTime(expirationTestDate)
                .claim("email", "testUserMail")
                .claim("name", "testUserName")
                .claim("oid", "testOid")
                .claim("preferred_username", "testUserUsername")
                .claim("rh", "ignored")
                .subject("testSubject")
                .claim("tid", "testTennantId")
                .claim("uti", "8UZ2eBjwiUDNU_LQSTJWAA")
                .claim("ver", "2.0")
                .build()
        );

        testIdToken.sign(rsaSigner);
    }
}
