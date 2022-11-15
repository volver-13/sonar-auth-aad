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

import com.microsoft.graph.authentication.IAuthenticationProvider;
import com.microsoft.graph.http.GraphServiceException;
import com.microsoft.graph.models.DirectoryObject;
import com.microsoft.graph.models.Group;
import com.microsoft.graph.requests.DirectoryObjectCollectionWithReferencesPage;
import com.microsoft.graph.requests.DirectoryObjectCollectionWithReferencesRequestBuilder;
import com.microsoft.graph.requests.GraphServiceClient;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import okhttp3.Request;
import org.sonar.api.server.authentication.UserIdentity;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import reactor.util.annotation.NonNull;
import reactor.util.annotation.Nullable;

import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

public class AadUserInfo {

    private String userOid;
    private String displayId;
    private String displayName;
    private String userEmail;

    //Initialized to an empty set so if group sync is enabled and no groups are
    //returned from the MS Graph call, user will be removed from all SQ groups.
    private Set<String> userGroups = Collections.emptySet();

    private static final Logger LOGGER = Loggers.get(AadUserInfo.class);

    public AadUserInfo(JWT idToken, AccessToken accessToken, Boolean wantGroups) throws ParseException {
        parseToken(idToken);

        if(Boolean.TRUE.equals(wantGroups)) {
            processGroups(accessToken.getValue());
        }
    }

    private void parseToken(JWT idToken) throws ParseException {
        // These are the names of the ID token claims we use below.
        final String USERNAME_CLAIM = "preferred_username";
        final String EMAIL_CLAIM = "email";
        final String DISPLAYNAME_CLAIM = "name";

        JWTClaimsSet claims = idToken.getJWTClaimsSet();

        // User's OID. Used for grabbing group membership if that feature is enabled
        if(claims.getStringClaim("oid") != null) {
            this.userOid = claims.getStringClaim("oid");
        }

        // Display ID
        // Tries the "preferred username" first, and falls back to email
        if(!"".equals(claims.getStringClaim(USERNAME_CLAIM)) && claims.getStringClaim(USERNAME_CLAIM) != null) {
            this.displayId = claims.getStringClaim(USERNAME_CLAIM);
        } else if(!claims.getStringClaim(EMAIL_CLAIM).isEmpty()) {
            this.displayId = claims.getStringClaim(EMAIL_CLAIM);
        }

        // Display Name
        // Attempts to get the user's name from the name claim. AAD requires
        // this, so it can't be blank. To be safe, we still set a display
        // name if that claim isn't in the token for some reason.
        if(!"".equals(claims.getStringClaim(DISPLAYNAME_CLAIM)) && claims.getStringClaim(DISPLAYNAME_CLAIM) != null) {
            this.displayName = claims.getStringClaim(DISPLAYNAME_CLAIM);
        } else {
            this.displayName = "No name provided";
        }

        // Email
        // Tries email first, and falls back to "preferred_username" if empty.
        // This should work for most AAD installs.
        if(!"".equals(claims.getStringClaim(EMAIL_CLAIM)) && claims.getStringClaim(EMAIL_CLAIM) != null) {
            this.userEmail = claims.getStringClaim(EMAIL_CLAIM);
        } else if(claims.getStringClaim(USERNAME_CLAIM) != null) {
            this.userEmail = claims.getStringClaim(USERNAME_CLAIM);
        }
    }

    public UserIdentity.Builder buildUserId(boolean includeGroups) {
        UserIdentity.Builder userIdentityBuilder = UserIdentity.builder()
            .setProviderLogin(getDisplayId())
            .setName(getDisplayName())
            .setEmail(getUserEmail());

        if (includeGroups) {
            userIdentityBuilder.setGroups(getUserGroups());
        }

        return userIdentityBuilder;
    }


    private void processGroups(String accessToken) {
        // We already have the auth code, so create a custom provider that will
        // return the code to our graph client.
        IAuthenticationProvider graphAuthProvider = new IAuthenticationProvider() {
            @NonNull
            @Override
            public CompletableFuture<String> getAuthorizationTokenAsync(URL requestUrl) {
                CompletableFuture<String> future = new CompletableFuture<>();
                future.complete(accessToken);
                return future;
            }
        };

        try {
            final GraphServiceClient<Request> graphClient =
                GraphServiceClient
                    .builder()
                    .authenticationProvider(graphAuthProvider)
                    .buildClient();

            DirectoryObjectCollectionWithReferencesPage memberGroupCollection =
                graphClient
                    .users(userOid).transitiveMemberOf()
                    .buildRequest()
                    .select("id,displayName")
                    .top(999) // Maximum page size of 999 to reduce number of requests.
                    .get();

            Set<String> parsedUserGroups = processMemberGroupCollection(memberGroupCollection);

            if(parsedUserGroups.isEmpty()) {
                LOGGER.warn("Group list was empty. Maybe your AAD permissions aren't set correctly?");
            }

            userGroups = parsedUserGroups;
        } catch (GraphServiceException e) {
            // Post the error to the logs, don't consider this fatal (fail auth)
            LOGGER.error("Group Membership Request failed with error: " + e.getMessage());
        }
    }

    Set<String> processMemberGroupCollection(@Nullable DirectoryObjectCollectionWithReferencesPage memberGroupCollection) {
        Set<String> parsedUserGroups = new HashSet<>();

        while(memberGroupCollection != null) {
            final List<DirectoryObject> groupList = memberGroupCollection.getCurrentPage();

            for ( DirectoryObject group : groupList) {
                String groupDisplayName = ((Group) group).displayName;

                // Don't add the group if the display name is null
                if(groupDisplayName != null) {
                    parsedUserGroups.add(groupDisplayName);
                }
            }

            final DirectoryObjectCollectionWithReferencesRequestBuilder nextPage = memberGroupCollection.getNextPage();
            if (nextPage == null) {
                break;
            } else {
                memberGroupCollection = nextPage.buildRequest().get();
            }
        }

        return parsedUserGroups;
    }

    public String getDisplayId() {
        return displayId;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getUserEmail() {
        return userEmail;
    }

    public Set<String> getUserGroups() {
        return userGroups;
    }
}
