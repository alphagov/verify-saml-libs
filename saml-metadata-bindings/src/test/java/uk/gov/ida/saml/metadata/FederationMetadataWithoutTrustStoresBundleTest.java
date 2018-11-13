package uk.gov.ida.saml.metadata;

import certificates.values.CACertificates;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import io.dropwizard.Configuration;
import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.testing.ConfigOverride;
import io.dropwizard.testing.ResourceHelpers;
import io.dropwizard.testing.junit.DropwizardAppRule;
import keystore.KeyStoreRule;
import keystore.builders.KeyStoreRuleBuilder;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.rules.RuleChain;
import org.junit.runner.RunWith;
import uk.gov.ida.saml.core.test.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.core.test.TestEntityIds;
import uk.gov.ida.saml.metadata.helpers.TestApplication;
import uk.gov.ida.saml.metadata.helpers.TestConfiguration;
import uk.gov.ida.saml.metadata.test.factories.metadata.MetadataFactory;

import javax.ws.rs.client.Client;
import javax.ws.rs.core.Response;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(OpenSAMLMockitoRunner.class)
public class FederationMetadataWithoutTrustStoresBundleTest {
    public static final WireMockRule metadataResource = new WireMockRule(WireMockConfiguration.options().dynamicPort());

    public static KeyStoreRule metadataKeyStoreRule = new KeyStoreRuleBuilder().withCertificate("metadata", CACertificates.TEST_METADATA_CA).withCertificate("root", CACertificates.TEST_ROOT_CA).build();

    static {
        metadataResource.stubFor(get(urlEqualTo("/metadata")).willReturn(aResponse().withBody(new MetadataFactory().defaultMetadata())));
    }

    public static final DropwizardAppRule<TestConfiguration> APPLICATION_DROPWIZARD_APP_RULE = new DropwizardAppRule<>(
        TestApplication.class,
        ResourceHelpers.resourceFilePath("test-app.yml"),
        ConfigOverride.config("metadata.uri", () -> "http://localhost:" + metadataResource.port() + "/metadata"),
        ConfigOverride.config("metadata.trustStore.path", () -> metadataKeyStoreRule.getAbsolutePath()),
        ConfigOverride.config("metadata.trustStore.password", () -> metadataKeyStoreRule.getPassword()),
        ConfigOverride.config("metadata.unknownProperty", () -> "unknownValue")
    );

    @ClassRule
    public final static RuleChain ruleChain = RuleChain.outerRule(metadataResource)
                                                       .around(metadataKeyStoreRule)
                                                       .around(APPLICATION_DROPWIZARD_APP_RULE);

    private static Client client;

    @BeforeClass
    public static void setUp() {
        client = new JerseyClientBuilder(APPLICATION_DROPWIZARD_APP_RULE.getEnvironment()).build(FederationMetadataWithoutTrustStoresBundleTest.class.getName() + "2");
    }

    @Test
    public void shouldReadMetadataFromMetadataServerUsingTrustStoreBackedMetadataConfiguration() {
        Response response = client.target("http://localhost:" + APPLICATION_DROPWIZARD_APP_RULE.getLocalPort() +"/foo").request().get();
        assertThat(response.readEntity(String.class)).isEqualTo(TestEntityIds.HUB_ENTITY_ID);
    }
}
