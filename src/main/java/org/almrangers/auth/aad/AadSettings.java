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

import java.util.Arrays;
import java.util.List;

import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.config.Settings;
import org.sonar.api.server.ServerSide;

import static java.lang.String.format;
import static java.lang.String.valueOf;
import static org.sonar.api.PropertyType.BOOLEAN;
import static org.sonar.api.PropertyType.SINGLE_SELECT_LIST;

@ServerSide
public class AadSettings {
  static final String CLIENT_ID = "sonar.auth.aad.clientId.secured";
  static final String CLIENT_SECRET = "sonar.auth.aad.clientSecret.secured";
    static final String ENABLED = "sonar.auth.aad.enabled";
    static final String ALLOW_USERS_TO_SIGN_UP = "sonar.auth.aad.allowUsersToSignUp";
    static final String TENANT_ID = "sonar.auth.aad.tenantId";
    static final String LOGIN_STRATEGY = "sonar.auth.aad.loginStrategy";
    static final String LOGIN_STRATEGY_UNIQUE = "Unique";
    static final String LOGIN_STRATEGY_PROVIDER_ID = "Same as Azure AD login";
    static final String LOGIN_STRATEGY_DEFAULT_VALUE = LOGIN_STRATEGY_UNIQUE;
    static final String MULTI_TENANT = "sonar.auth.aad.multiTenant";

    static final String CATEGORY = "Azure Active Directory";
    static final String SUBCATEGORY = "Authentication";

    static final String ROOT_URL = "https://login.microsoftonline.com";
    static final String AUTHORIZATION_URL = "oauth2/authorize";
    static final String AUTHORITY_URL = "oauth2/token";
    static final String COMMON_URL = "common";
    static final String SECURE_RESOURCE_URL = "https://graph.windows.net";
    static final String AUTH_REQUEST_FORMAT = "%s?client_id=%s&response_type=code&redirect_uri=%s&state=%s";

    private final Settings settings;

    public AadSettings(Settings settings) {
        this.settings = settings;
    }

    public static List<PropertyDefinition> definitions() {
        return Arrays.asList(
                PropertyDefinition.builder(ENABLED)
                        .name("Enabled")
                        .description("Enable Azure AD users to login. Value is ignored if client ID and secret are not defined.")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(BOOLEAN)
                        .defaultValue(valueOf(false))
                        .index(1)
                        .build(),
                PropertyDefinition.builder(CLIENT_ID)
                        .name("Client ID")
                        .description("Client ID provided by Azure AD when registering the application.")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .index(2)
                        .build(),
                PropertyDefinition.builder(CLIENT_SECRET)
                        .name("Client Secret")
                        .description("Client key provided by Azure AD when registering the application.")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .index(3)
                        .build(),
                PropertyDefinition.builder(MULTI_TENANT)
                        .name("Multi-tenant Azure Application")
                        .description("multi-tenant application")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(BOOLEAN)
                        .defaultValue(valueOf(false))
                        .index(4)
                        .build(),
                PropertyDefinition.builder(TENANT_ID)
                        .name("Tenant ID")
                        .description("Azure AD Tenant ID.")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .index(5)
                        .build(),
                PropertyDefinition.builder(ALLOW_USERS_TO_SIGN_UP)
                        .name("Allow users to sign-up")
                        .description("Allow new users to authenticate. When set to 'false', only existing users will be able to authenticate to the server.")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(BOOLEAN)
                        .defaultValue(valueOf(true))
                        .index(6)
                        .build(),
                PropertyDefinition.builder(LOGIN_STRATEGY)
                        .name("Login generation strategy")
                        .description(format("When the login strategy is set to '%s', the user's login will be auto-generated the first time so that it is unique. " +
                                        "When the login strategy is set to '%s', the user's login will be the Azure AD login.",
                                LOGIN_STRATEGY_UNIQUE, LOGIN_STRATEGY_PROVIDER_ID))
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(SINGLE_SELECT_LIST)
                        .defaultValue(LOGIN_STRATEGY_DEFAULT_VALUE)
                        .options(LOGIN_STRATEGY_UNIQUE, LOGIN_STRATEGY_PROVIDER_ID)
                        .index(7)
                        .build()

        );
    }

    public String clientId() {
        return settings.getString(CLIENT_ID);
    }

    public boolean allowUsersToSignUp() {
        return settings.getBoolean(ALLOW_USERS_TO_SIGN_UP);
    }
    public boolean multiTenant() {
        return settings.getBoolean(MULTI_TENANT);
    }

    public String tenantId() {
        return settings.getString(TENANT_ID);
    }

    public String clientSecret() {
        return settings.getString(CLIENT_SECRET);
    }

    public boolean isEnabled() {
        return settings.getBoolean(ENABLED) && clientId() != null && clientSecret() != null && loginStrategy() != null;
    }

    private String getEndpoint() {
        if(multiTenant())
            return COMMON_URL;
        else
            return tenantId();
    }

    public String authorizationUrl() {
        return String.format("%s/%s/%s", ROOT_URL, getEndpoint(), AUTHORIZATION_URL);
    }

    public String authorityUrl() {
            return String.format("%s/%s/%s", ROOT_URL, getEndpoint(), AUTHORITY_URL);
    }

    public String loginStrategy() {
        return settings.getString(LOGIN_STRATEGY);
    }
}