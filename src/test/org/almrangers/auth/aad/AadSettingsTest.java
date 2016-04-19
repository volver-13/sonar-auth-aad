package org.almrangers.auth.aad;

import org.junit.Test;
import org.sonar.api.config.PropertyDefinitions;
import org.sonar.api.config.Settings;

import static org.almrangers.auth.aad.AadSettings.LOGIN_STRATEGY_DEFAULT_VALUE;
import static org.assertj.core.api.Assertions.assertThat;

public class AadSettingsTest {
    Settings settings = new Settings(new PropertyDefinitions(AadSettings.definitions()));

    AadSettings underTest = new AadSettings(settings);

    @Test
    public void is_enabled() {
        settings.setProperty("sonar.auth.aad.clientId.secured", "id");
        settings.setProperty("sonar.auth.aad.clientSecret.secured", "secret");
        settings.setProperty("sonar.auth.aad.loginStrategy", LOGIN_STRATEGY_DEFAULT_VALUE);

        settings.setProperty("sonar.auth.aad.enabled", true);
        assertThat(underTest.isEnabled()).isTrue();

        settings.setProperty("sonar.auth.aad.enabled", false);
        assertThat(underTest.isEnabled()).isFalse();
    }

    @Test
    public void is_enabled_always_return_false_when_client_id_is_null() {
        settings.setProperty("sonar.auth.aad.enabled", true);
        settings.setProperty("sonar.auth.aad.clientId.secured", (String) null);
        settings.setProperty("sonar.auth.aad.clientSecret.secured", "secret");
        settings.setProperty("sonar.auth.aad.loginStrategy", LOGIN_STRATEGY_DEFAULT_VALUE);

        assertThat(underTest.isEnabled()).isFalse();
    }

    @Test
    public void is_enabled_always_return_false_when_client_secret_is_null() {
        settings.setProperty("sonar.auth.aad.enabled", true);
        settings.setProperty("sonar.auth.aad.clientId.secured", "id");
        settings.setProperty("sonar.auth.aad.clientSecret.secured", (String) null);
        settings.setProperty("sonar.auth.aad.loginStrategy", LOGIN_STRATEGY_DEFAULT_VALUE);

        assertThat(underTest.isEnabled()).isFalse();
    }

    @Test
    public void default_login_strategy_is_unique_login() {
        assertThat(underTest.loginStrategy()).isEqualTo(AadSettings.LOGIN_STRATEGY_UNIQUE);
    }

    @Test
    public void return_client_id() {
        settings.setProperty("sonar.auth.aad.clientId.secured", "id");
        assertThat(underTest.clientId()).isEqualTo("id");
    }

    @Test
    public void return_client_secret() {
        settings.setProperty("sonar.auth.aad.clientSecret.secured", "secret");
        assertThat(underTest.clientSecret()).isEqualTo("secret");
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
        assertThat(AadSettings.definitions()).hasSize(8);
    }


}