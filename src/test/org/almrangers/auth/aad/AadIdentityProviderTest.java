package org.almrangers.auth.aad;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.sonar.api.config.Settings;
import org.sonar.api.server.authentication.OAuth2IdentityProvider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;


public class AadIdentityProviderTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();
    Settings settings = new Settings();
    AadSettings aadSettings = new AadSettings(settings);
    AadIdentityProvider underTest = new AadIdentityProvider(aadSettings);

    @Test
    public void check_fields() throws Exception {
        assertThat(underTest.getKey()).isEqualTo("aad");
        assertThat(underTest.getName()).isEqualTo("Azure AD");
        assertThat(underTest.getDisplay().getIconPath()).isEqualTo("/static/authaad/azure.svg");
        assertThat(underTest.getDisplay().getBackgroundColor()).isEqualTo("#336699");
    }

    @Test
    public void init() throws Exception {
        setSettings(true);
        OAuth2IdentityProvider.InitContext context = mock(OAuth2IdentityProvider.InitContext.class);
        when(context.generateCsrfState()).thenReturn("state");
        when(context.getCallbackUrl()).thenReturn("http://localhost/callback");

        underTest.init(context);

        verify(context).redirectTo("https://login.microsoftonline.com/null/oauth2/authorize?client_id=id&response_type=code&redirect_uri=http://localhost/callback&state=state");
    }

    @Test
    public void is_enabled() throws Exception {
        settings.setProperty("sonar.auth.aad.clientId.secured", "id");
        settings.setProperty("sonar.auth.aad.clientSecret.secured", "secret");
        settings.setProperty("sonar.auth.aad.loginStrategy", AadSettings.LOGIN_STRATEGY_DEFAULT_VALUE);
        settings.setProperty("sonar.auth.aad.enabled", true);
        assertThat(underTest.isEnabled()).isTrue();

        settings.setProperty("sonar.auth.aad.enabled", false);
        assertThat(underTest.isEnabled()).isFalse();
    }

    private void setSettings(boolean enabled) {
        if (enabled) {
            settings.setProperty("sonar.auth.aad.clientId.secured", "id");
            settings.setProperty("sonar.auth.aad.clientSecret.secured", "secret");
            settings.setProperty("sonar.auth.aad.loginStrategy", AadSettings.LOGIN_STRATEGY_DEFAULT_VALUE);
            settings.setProperty("sonar.auth.aad.enabled", true);
        } else {
            settings.setProperty("sonar.auth.aad.enabled", false);
        }
    }

}