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

import static org.assertj.core.api.Assertions.assertThat;

import java.text.ParseException;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.microsoft.graph.logger.DefaultLogger;
import com.microsoft.graph.requests.DirectoryObjectCollectionResponse;
import com.microsoft.graph.requests.DirectoryObjectCollectionWithReferencesPage;
import com.microsoft.graph.serializer.DefaultSerializer;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.Before;
import org.junit.Test;
import org.sonar.api.server.authentication.UserIdentity;

public class AadUserInfoTest {

    String testTennantId = "ff4d5470-f7f3-4603-900d-cb291dc340bd";
    String testAudience = "fbfc665d-79c1-45b6-aa56-d66c3d64f63c";
    String testSubject = "0.AQPR2ObdWaKTqn-ixSd3lY55gUGQJKwcOixphE53Gb9sTyiO2sv.";
    String testOid = "377ae852-940f-4e0a-b154-563b7427a3dc";
    String testUserMail = "john.doe@example.com";
    String testUserUsername = "john.doe@example.net";
    String testUserName = "John Doe";

    // All the different tokens we need to test.
    // The "No*" tokens are to test specific logic in the token parsing for user info.
    PlainJWT testIdToken;
    PlainJWT testIdTokenNoName;
    PlainJWT testIdTokenNoMail;
    PlainJWT testIdTokenNoUsername;
    AadUserInfo userInfo;

    // A group object for testing the group parser
    DirectoryObjectCollectionWithReferencesPage memberGroupCollection;

    @Test
    public void test_token_parsing() throws ParseException {
        userInfo = new AadUserInfo(testIdToken, new BearerAccessToken(), false);

        assertThat(userInfo).isInstanceOf(AadUserInfo.class);
    }

    @Test
    public void test_token_claims() throws ParseException {
        userInfo = new AadUserInfo(testIdToken, new BearerAccessToken(), false);

        assertThat(userInfo.getDisplayId()).isEqualTo(testUserUsername);
        assertThat(userInfo.getDisplayName()).isEqualTo(testUserName);
        assertThat(userInfo.getUserEmail()).isEqualTo(testUserMail);

        // No groups were parsed, so we should get an empty set
        assertThat(userInfo.getUserGroups()).isEqualTo(Collections.emptySet());

        // Test for the "no name claim" scenario
        userInfo = new AadUserInfo(testIdTokenNoName, new BearerAccessToken(), false);

        assertThat(userInfo.getDisplayName()).isEqualTo("No name provided");

        // Test for the "no email claim" scenario
        userInfo = new AadUserInfo(testIdTokenNoMail, new BearerAccessToken(), false);

        assertThat(userInfo.getUserEmail()).isEqualTo(testUserUsername);

        // Test for the "no username claim" scenario
        userInfo = new AadUserInfo(testIdTokenNoUsername, new BearerAccessToken(), false);

        assertThat(userInfo.getDisplayId()).isEqualTo(testUserMail);
    }

    @Test
    public void returns_user_id_builder() throws ParseException {
        userInfo = new AadUserInfo(testIdToken, new BearerAccessToken(), false);

        UserIdentity userId = userInfo.buildUserId(true).build();

        assertThat(userId.getEmail()).isEqualTo(testUserMail);
        assertThat(userId.getName()).isEqualTo(testUserName);

        // Since no groups were passed in to build the user,
        // getting the groups should return an empty set.
        assertThat(userId.getGroups()).isEqualTo(Collections.emptySet());
    }

    @Test
    // This tests that parsing will still work without errors in the event that the
    // group fetch doesn't work. For this test, it's because of an invalid token.
    public void test_empty_group_parsing() throws ParseException {
        userInfo = new AadUserInfo(testIdToken, new BearerAccessToken(), true);

        assertThat(userInfo).isInstanceOf(AadUserInfo.class);
        assertThat(userInfo.getUserGroups()).isEqualTo(Collections.emptySet());
    }

    @Test
    public void parse_member_groups() throws ParseException {
        Set<String> expectedGroups = new HashSet<>(Arrays.asList("Administrators", "Developers"));

        userInfo = new AadUserInfo(testIdToken, new BearerAccessToken(), false);

        Set<String> memberships = userInfo.processMemberGroupCollection(memberGroupCollection);

        assertThat(memberships).isEqualTo(expectedGroups);
    }

    @Before
    public void setUp() {
        // Build the object for parsing AAD Group Responses
        createAadGroupResponse();

        // Get current date/time for the test token
        Calendar testCalendar = Calendar.getInstance();
        Date currentTestDate = testCalendar.getTime();

        // Set up a 1 hour expiration for the test token
        testCalendar.add(Calendar.HOUR, 1);
        Date expirationTestDate = testCalendar.getTime();


        // This token is based on the ID token returned from MS ID Platform OAuth v2.0
        // see: https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/active-directory/develop/id-tokens.md
        testIdToken = new PlainJWT(
            new JWTClaimsSet.Builder()
                .audience(testAudience)
                .issuer("https://login.microsoftonline.com/" + testTennantId + "/v2.0")
                .issueTime(currentTestDate)
                .notBeforeTime(currentTestDate)
                .expirationTime(expirationTestDate)
                .claim("email", testUserMail)
                .claim("name", testUserName)
                .claim("oid", testOid)
                .claim("preferred_username", testUserUsername)
                .claim("rh", "ignored")
                .subject(testSubject)
                .claim("tid", testTennantId)
                .claim("uti", "8UZ2eBjwiUDNU_LQSTJWAA")
                .claim("ver", "2.0")
                .build());

        // This is to specifically test when no name is passed in the ID token
        // (This should be impossible, as name is required for accounts.)
        testIdTokenNoName = new PlainJWT(
            new JWTClaimsSet.Builder()
                .audience(testAudience)
                .issuer("https://login.microsoftonline.com/" + testTennantId + "/v2.0")
                .issueTime(currentTestDate)
                .notBeforeTime(currentTestDate)
                .expirationTime(expirationTestDate)
                .claim("email", testUserMail)
                .claim("oid", testOid)
                .claim("preferred_username", testUserUsername)
                .claim("rh", "ignored")
                .subject(testSubject)
                .claim("tid", testTennantId)
                .claim("uti", "8UZ2eBjwiUDNU_LQSTJWAA")
                .claim("ver", "2.0")
                .build());

        // This is to test when no email claim is passed in the ID token.
        testIdTokenNoMail = new PlainJWT(
            new JWTClaimsSet.Builder()
                .audience(testAudience)
                .issuer("https://login.microsoftonline.com/" + testTennantId + "/v2.0")
                .issueTime(currentTestDate)
                .notBeforeTime(currentTestDate)
                .expirationTime(expirationTestDate)
                .claim("name", testUserName)
                .claim("oid", testOid)
                .claim("preferred_username", testUserUsername)
                .claim("rh", "ignored")
                .subject(testSubject)
                .claim("tid", testTennantId)
                .claim("uti", "8UZ2eBjwiUDNU_LQSTJWAA")
                .claim("ver", "2.0")
                .build());

        // This is to test when the preferred_username claim isn't present in the ID token.
        testIdTokenNoUsername = new PlainJWT(
            new JWTClaimsSet.Builder()
                .audience(testAudience)
                .issuer("https://login.microsoftonline.com/" + testTennantId + "/v2.0")
                .issueTime(currentTestDate)
                .notBeforeTime(currentTestDate)
                .expirationTime(expirationTestDate)
                .claim("email", testUserMail)
                .claim("name", testUserName)
                .claim("oid", testOid)
                .claim("rh", "ignored")
                .subject(testSubject)
                .claim("tid", testTennantId)
                .claim("uti", "8UZ2eBjwiUDNU_LQSTJWAA")
                .claim("ver", "2.0")
                .build());
    }

    void createAadGroupResponse() {
        // This object is a direct copy of the MS Graph response with the ID
        // being changed from the real value.
        JsonObject jsonObj = new Gson().fromJson("{\n" +
                "  \"@odata.context\": \"https://graph.microsoft.com/v1.0/$metadata#directoryObjects(id,displayName)\",\n" +
                "  \"value\": [\n" +
                "    {\n" +
                "      \"@odata.type\": \"#microsoft.graph.group\",\n" +
                "      \"id\": \"89fb503f-134f-43cd-aaa7-f21facb2eca3\",\n" +
                "      \"displayName\": \"Developers\"\n" +
                "    },\n" +
                "    {\n" +
                "      \"@odata.type\": \"#microsoft.graph.group\",\n" +
                "      \"id\": \"d595c0e2-28f4-4a52-8ec5-58eab17309f8\",\n" +
                "      \"displayName\": \"Administrators\"\n" +
                "    }\n" +
                "  ]\n" +
                "}",
            JsonObject.class);

        DefaultSerializer serializer = new DefaultSerializer(new DefaultLogger());

        DirectoryObjectCollectionResponse memberResponse = serializer.deserializeObject(jsonObj, DirectoryObjectCollectionResponse.class);

        assert memberResponse != null;
        memberGroupCollection = new DirectoryObjectCollectionWithReferencesPage(memberResponse, null);
    }
}
