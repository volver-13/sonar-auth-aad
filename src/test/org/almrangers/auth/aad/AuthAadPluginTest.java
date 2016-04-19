package org.almrangers.auth.aad;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


public class AuthAadPluginTest {
    AuthAadPlugin underTest = new AuthAadPlugin();

    @Test
    public void test_extensions() throws Exception {
        assertThat(underTest.getExtensions()).hasSize(10);
    }

}