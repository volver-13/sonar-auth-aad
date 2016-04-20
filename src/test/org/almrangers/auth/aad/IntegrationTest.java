package org.almrangers.auth.aad;

import com.squareup.okhttp.mockwebserver.MockWebServer;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.sonar.api.config.PropertyDefinitions;
import org.sonar.api.config.Settings;
import org.sonar.api.server.authentication.OAuth2IdentityProvider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class IntegrationTest {
    private static final String CALLBACK_URL = "http://localhost/oauth/callback/github";

    @Rule
    public MockWebServer aad = new MockWebServer();

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    // load settings with default values
    Settings settings = new Settings(new PropertyDefinitions(AadSettings.definitions()));
    AadSettings aadSettings = new AadSettings(settings);
    AadIdentityProvider underTest = new AadIdentityProvider(aadSettings);

    @Before
    public void enable() {
        settings.setProperty("sonar.auth.aad.clientId.secured", "the_id");
        settings.setProperty("sonar.auth.aad.clientSecret.secured", "the_secret");
        settings.setProperty("sonar.auth.aad.enabled", true);
    }

    @Test
    public void redirect_browser_to_aad_authentication_form() throws Exception {
        DumbInitContext context = new DumbInitContext("the-csrf-state");
        underTest.init(context);

    }


    private static class DumbInitContext implements OAuth2IdentityProvider.InitContext {
        private final String generatedCsrfState;
        String redirectedTo = null;

        public DumbInitContext(String generatedCsrfState) {
            this.generatedCsrfState = generatedCsrfState;
        }

        @Override
        public String generateCsrfState() {
            return generatedCsrfState;
        }

        @Override
        public void redirectTo(String url) {
            this.redirectedTo = url;
        }

        @Override
        public String getCallbackUrl() {
            return CALLBACK_URL;
        }

        @Override
        public HttpServletRequest getRequest() {
            return null;
        }

        @Override
        public HttpServletResponse getResponse() {
            return null;
        }
    }
}
