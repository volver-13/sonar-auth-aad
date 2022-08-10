/**
 * Azure Active Directory Authentication Plugin for SonarQube
 * <p>
 * Copyright (c) 2016 Microsoft Corporation
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

import org.junit.Test;
import org.sonar.api.config.PropertyDefinitions;
import org.sonar.api.config.internal.MapSettings;

import static org.almrangers.auth.aad.AadSettings.*;
import static org.assertj.core.api.Assertions.assertThat;

public class AadSettingsTest {
  MapSettings settings = new MapSettings(new PropertyDefinitions(AadSettings.definitions()));

  AadSettings underTest = new AadSettings(settings.asConfig());

  @Test
  public void is_enabled() {
    settings.setProperty("sonar.auth.aad.clientId.secured", "id");
    settings.setProperty("sonar.auth.aad.clientSecret.secured", "secret");

    settings.setProperty("sonar.auth.aad.enabled", true);
    assertThat(underTest.isEnabled()).isTrue();

    settings.setProperty("sonar.auth.aad.enabled", false);
    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void return_authorization_authority_url_for_single_tenant_azureAd_app() {
    settings.setProperty("sonar.auth.aad.multiTenant", "false");
    settings.setProperty("sonar.auth.aad.tenantId", "tenantId");
    assertThat(underTest.authorizationUrl()).isEqualTo("https://login.microsoftonline.com/tenantId/oauth2/v2.0/authorize");
    assertThat(underTest.authorityUrl()).isEqualTo("https://login.microsoftonline.com/tenantId/oauth2/v2.0/token");
  }

  @Test
  public void return_authorization_authority_url_for_multi_tenant_azureAd_app() {
    settings.setProperty("sonar.auth.aad.multiTenant", "true");
    assertThat(underTest.authorizationUrl()).isEqualTo("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
    assertThat(underTest.authorityUrl()).isEqualTo("https://login.microsoftonline.com/common/oauth2/v2.0/token");
  }

  @Test
  public void return_correct_urls() {
    // This tenant ID is used for the JWK Keys URL. The below GUID was generated randomly and has no meaning outside testing.
    settings.setProperty("sonar.auth.aad.tenantId", "6664a665-d25b-40ac-8ab4-e27b014c2464");

    //Azure Default "Global"
    settings.setProperty("sonar.auth.aad.directoryLocation", DIRECTORY_LOC_GLOBAL);
    assertThat(underTest.authorizationUrl()).startsWith("https://login.microsoftonline.com");
    assertThat(underTest.getGraphURL()).startsWith("https://graph.microsoft.com");
    assertThat(underTest.jwkKeysUrl()).isEqualTo("https://login.microsoftonline.com/6664a665-d25b-40ac-8ab4-e27b014c2464/discovery/keys");

    //Azure US Gov
    settings.setProperty("sonar.auth.aad.directoryLocation", DIRECTORY_LOC_USGOV);
    assertThat(underTest.authorizationUrl()).startsWith("https://login.microsoftonline.us");
    assertThat(underTest.getGraphURL()).startsWith("https://graph.microsoft.com");
    assertThat(underTest.jwkKeysUrl()).isEqualTo("https://login.microsoftonline.us/6664a665-d25b-40ac-8ab4-e27b014c2464/discovery/keys");

    //Azure China
    settings.setProperty("sonar.auth.aad.directoryLocation", DIRECTORY_LOC_CN);
    assertThat(underTest.authorizationUrl()).startsWith("https://login.chinacloudapi.cn");
    assertThat(underTest.getGraphURL()).startsWith("https://microsoftgraph.chinacloudapi.cn");
    assertThat(underTest.jwkKeysUrl()).isEqualTo("https://login.chinacloudapi.cn/6664a665-d25b-40ac-8ab4-e27b014c2464/discovery/keys");
  }

  @Test
  public void return_graph_membership_url() {
    settings.setProperty("sonar.auth.aad.directoryLocation", DIRECTORY_LOC_GLOBAL);
    assertThat(underTest.getGraphMembershipUrl()).isEqualTo("https://graph.microsoft.com/v1.0/%s/users/%s/transitiveMemberOf");
  }

  @Test
  public void is_enabled_always_return_false_when_client_id_is_null() {
    settings.setProperty("sonar.auth.aad.enabled", true);
    //noinspection ConstantConditions
    settings.setProperty("sonar.auth.aad.clientId.secured", (String) null);
    settings.setProperty("sonar.auth.aad.clientSecret.secured", "secret");

    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void is_enabled_always_return_false_when_client_secret_is_null() {
    settings.setProperty("sonar.auth.aad.enabled", true);
    settings.setProperty("sonar.auth.aad.clientId.secured", "id");
    //noinspection ConstantConditions
    settings.setProperty("sonar.auth.aad.clientSecret.secured", (String) null);

    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void return_client_id() {
    settings.setProperty("sonar.auth.aad.clientId.secured", "id");
    assertThat(underTest.clientId().orElse(null)).isEqualTo("id");
  }

  @Test
  public void return_client_secret() {
    settings.setProperty("sonar.auth.aad.clientSecret.secured", "secret");
    assertThat(underTest.clientSecret().orElse(null)).isEqualTo("secret");
  }

  @Test
  public void return_group_sync() {
    settings.setProperty("sonar.auth.aad.enableGroupsSync", true);
    assertThat(underTest.enableGroupSync()).isTrue();
    settings.setProperty("sonar.auth.aad.enableGroupsSync", false);
    assertThat(underTest.enableGroupSync()).isFalse();
  }

  @Test
  public void return_client_cred_when_multiTenant_is_false() {
    settings.setProperty("sonar.auth.aad.multiTenant", "false");

    settings.setProperty("sonar.auth.aad.enableClientCredential", true);
    assertThat(underTest.enableClientCredential()).isTrue();
    settings.setProperty("sonar.auth.aad.enableClientCredential", false);
    assertThat(underTest.enableClientCredential()).isFalse();
  }

  @Test
  public void client_cred_always_return_false_when_multiTenant_is_true() {
    settings.setProperty("sonar.auth.aad.multiTenant", "true");

    settings.setProperty("sonar.auth.aad.enableClientCredential", true);
    assertThat(underTest.enableClientCredential()).isFalse();
    settings.setProperty("sonar.auth.aad.enableClientCredential", false);
    assertThat(underTest.enableClientCredential()).isFalse();
  }

  @Test
  public void return_authority_url() {
    // Just do a quick test with the global location to verify the URL is built properly
    settings.setProperty("sonar.auth.aad.directoryLocation", "Azure AD (Global)");
    settings.setProperty("sonar.auth.aad.tenantId", "    123e4567-e89b-12d3-a456-426655440000");
    assertThat(underTest.authorityUrl()).isEqualTo("https://login.microsoftonline.com/123e4567-e89b-12d3-a456-426655440000/oauth2/v2.0/token");
  }

  @Test
  public void allow_users_to_sign_up() {
    settings.setProperty("sonar.auth.aad.allowUsersToSignUp", "true");
    assertThat(underTest.allowUsersToSignUp()).isTrue();

    settings.setProperty("sonar.auth.aad.allowUsersToSignUp", "false");
    assertThat(underTest.allowUsersToSignUp()).isFalse();
  }

  @Test
  public void definitions() {
    assertThat(AadSettings.definitions()).hasSize(9);
  }
}
