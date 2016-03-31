/**
 * Azure Active Directory Authentication Plugin for SonarQube

 * Copyright (c) 2016 Microsoft Corporation
 * All rights reserved.
 *
 * The MIT License (MIT)

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package org.almrangers.auth.aad;


import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.aad.adal4j.UserInfo;

import java.net.URI;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.servlet.http.HttpServletRequest;

import org.sonar.api.server.ServerSide;
import org.sonar.api.server.authentication.Display;
import org.sonar.api.server.authentication.OAuth2IdentityProvider;
import org.sonar.api.server.authentication.UserIdentity;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import static java.lang.String.format;
import static org.almrangers.auth.aad.AadSettings.*;

@ServerSide
public class AadIdentityProvider implements OAuth2IdentityProvider {
    private static final Logger LOGGER = Loggers.get(AadIdentityProvider.class);

    private final AadSettings settings;

    public AadIdentityProvider(AadSettings settings) {
        this.settings = settings;
    }


    @Override
    public Display getDisplay() {
        return Display.builder()
                .setIconPath("/static/authaad/azure.svg")
                .setBackgroundColor("#336699")
                .build();
    }

    @Override
    public String getKey() {
        return "aad";
    }

    @Override
    public String getName() {
        return "Azure AD";
    }

    @Override
    public boolean isEnabled() {
        return settings.isEnabled();
    }

    @Override
    public boolean allowsUsersToSignUp() {
        return settings.allowUsersToSignUp();
    }

    @Override
    public void init(InitContext context) {
        String state = context.generateCsrfState();
        String authUrl = String.format(AUTH_REQUEST_FORMAT,settings.authorizationUrl(),settings.clientId(),context.getCallbackUrl(),state);
        context.redirectTo(authUrl);
    }

    @Override
    public void callback(CallbackContext context) {
        context.verifyCsrfState();
        HttpServletRequest request = context.getRequest();
        String oAuthVerifier = request.getParameter("code");
        AuthenticationContext authContext;
        AuthenticationResult result;
        ExecutorService service = null;

        try {
            service = Executors.newFixedThreadPool(1);
            authContext = new AuthenticationContext(settings.authorityUrl(), false, service);
            URI url = new URI(context.getCallbackUrl());
            ClientCredential clientCredt = new ClientCredential(settings.clientId(), settings.clientSecret());
            Future<AuthenticationResult> future = authContext.acquireTokenByAuthorizationCode(
                    oAuthVerifier, url, clientCredt, SECURE_RESOURCE_URL, null);
            result = future.get();

            UserInfo aadUser = result.getUserInfo();
            UserIdentity userIdentity = UserIdentity.builder()
                    .setProviderLogin(getName())
                    .setLogin(getLogin(aadUser))
                    .setName(aadUser.getGivenName() + " " + aadUser.getFamilyName())
                    .setEmail(aadUser.getDisplayableId())
                    .build();
            context.authenticate(userIdentity);
            context.redirectToRequestedPage();
        } catch (Exception e) {
            LOGGER.error("Exception:" + e.toString());
            if (service != null) {
                service.shutdown();
            }
            //ugly but required to force redirection to unauthorized page
            //ToDO: use the supported API once available ... check SONAR-7444 [https://jira.sonarsource.com/browse/SONAR-7444]
            throw new IllegalStateException(format("Fail to authenticate the user:%s", e.toString()));

        }
    }

    private String getLogin(UserInfo aadUser) {
        String loginStrategy = settings.loginStrategy();
        if (LOGIN_STRATEGY_UNIQUE.equals(loginStrategy)) {
            return generateUniqueLogin(aadUser);
        } else if (LOGIN_STRATEGY_PROVIDER_ID.equals(loginStrategy)) {
            return aadUser.getDisplayableId();
        } else {
            throw new IllegalStateException(format("Login strategy not found : %s", loginStrategy));
        }
    }

    private String generateUniqueLogin(UserInfo aadUser) {
        return String.format("%s@%s",aadUser.getDisplayableId(),getKey());
    }

}
