package uk.gov.ida.saml.metadata.bundle;

import com.codahale.metrics.health.HealthCheck;
import com.codahale.metrics.health.HealthCheckRegistry;
import io.dropwizard.Configuration;
import io.dropwizard.setup.Environment;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import uk.gov.ida.saml.metadata.MetadataResolverConfiguration;
import uk.gov.ida.saml.metadata.factories.CredentialResolverFactory;
import uk.gov.ida.saml.metadata.factories.DropwizardMetadataResolverFactory;
import uk.gov.ida.saml.metadata.factories.MetadataSignatureTrustEngineFactory;

import java.net.URI;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class MetadataResolverBundleTest {

    @Mock
    private MetadataResolverConfiguration configuration;

    @Mock
    private Environment environment;

    @Mock
    private CredentialResolverFactory credentialResolverFactory;

    @Mock
    private DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory;

    @Mock
    private MetadataSignatureTrustEngineFactory metadataSignatureTrustEngineFactory;

    @Mock
    private MetadataResolver metadataResolver;

    @Mock
    private ExplicitKeySignatureTrustEngine signatureTrustEngine;

    @Mock
    private MetadataCredentialResolver credentialResolver;

    @Mock
    private HealthCheckRegistry healthCheckRegistry;

    @Test
    public void shouldValidateSignatureAndRegisterHealthcheckWithDefaultBuilder() throws Exception {

        MetadataResolverBundle bundle = new MetadataResolverBundle.Builder<>(TestConfiguration::getMetadataConfiguration)
                .withCredentialResolverFactory(credentialResolverFactory)
                .withDropwizardMetadataResolverFactory(dropwizardMetadataResolverFactory)
                .withMetadataSignatureTrustEngineFactory(metadataSignatureTrustEngineFactory)
                .build();

        when(dropwizardMetadataResolverFactory.createMetadataResolver(environment, configuration, true))
                .thenReturn(metadataResolver);
        when(metadataSignatureTrustEngineFactory.createSignatureTrustEngine(metadataResolver))
                .thenReturn(signatureTrustEngine);
        when(credentialResolverFactory.create(metadataResolver))
                .thenReturn(credentialResolver);
        when(environment.healthChecks()).thenReturn(healthCheckRegistry);
        when(configuration.getUri()).thenReturn(URI.create("http://entity.id"));

        bundle.run(new TestConfiguration(configuration), environment);

        verify(environment).healthChecks();
        verify(healthCheckRegistry).register(eq("http://entity.id"), any(HealthCheck.class));

    }


    @Test
    public void shouldNotRegisterHealthcheckWhenBundleBuiltWithHealthchecksFalse() throws Exception {

        MetadataResolverBundle bundle = new MetadataResolverBundle.Builder<>(TestConfiguration::getMetadataConfiguration)
                .withCredentialResolverFactory(credentialResolverFactory)
                .withDropwizardMetadataResolverFactory(dropwizardMetadataResolverFactory)
                .withMetadataSignatureTrustEngineFactory(metadataSignatureTrustEngineFactory)
                .withHealthcheck(false)
                .build();

        when(dropwizardMetadataResolverFactory.createMetadataResolver(environment, configuration, true))
                .thenReturn(metadataResolver);
        when(metadataSignatureTrustEngineFactory.createSignatureTrustEngine(metadataResolver))
                .thenReturn(signatureTrustEngine);
        when(credentialResolverFactory.create(metadataResolver))
                .thenReturn(credentialResolver);

        bundle.run(new TestConfiguration(configuration), environment);

        verify(environment, never()).healthChecks();

    }

    class TestConfiguration extends Configuration {

        private final MetadataResolverConfiguration metadataConfiguration;

        TestConfiguration(MetadataResolverConfiguration metadataConfiguration) {
            this.metadataConfiguration = metadataConfiguration;
        }

        Optional<MetadataResolverConfiguration> getMetadataConfiguration() {
            return Optional.of(metadataConfiguration);
        }
    }

}