package uk.gov.ida.saml.metadata.bundle;

import com.google.inject.Module;
import io.dropwizard.Configuration;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import uk.gov.ida.saml.metadata.MetadataHealthCheck;
import uk.gov.ida.saml.metadata.MetadataResolverConfiguration;
import uk.gov.ida.saml.metadata.exception.MetadataResolverCreationException;
import uk.gov.ida.saml.metadata.factories.CredentialResolverFactory;
import uk.gov.ida.saml.metadata.factories.DropwizardMetadataResolverFactory;
import uk.gov.ida.saml.metadata.factories.MetadataSignatureTrustEngineFactory;

import javax.annotation.Nullable;
import javax.inject.Provider;
import java.util.Optional;

public class MetadataResolverBundle<T extends Configuration> implements io.dropwizard.ConfiguredBundle<T> {
    private final MetadataConfigurationExtractor<T> configExtractor;
    private final MetadataSignatureTrustEngineFactory metadataSignatureTrustEngineFactory;
    private final CredentialResolverFactory credentialResolverFactory;
    private MetadataResolver metadataResolver;
    private final DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory;
    private ExplicitKeySignatureTrustEngine signatureTrustEngine;
    private MetadataCredentialResolver credentialResolver;
    private final boolean validateSignatures;
    private final boolean healthcheck;

    private MetadataResolverBundle(MetadataConfigurationExtractor<T> configExtractor, MetadataSignatureTrustEngineFactory metadataSignatureTrustEngineFactory, CredentialResolverFactory credentialResolverFactory, DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory, boolean validateSignatures, boolean healthcheck) {
        this.configExtractor = configExtractor;
        this.metadataSignatureTrustEngineFactory = metadataSignatureTrustEngineFactory;
        this.credentialResolverFactory = credentialResolverFactory;
        this.dropwizardMetadataResolverFactory = dropwizardMetadataResolverFactory;
        this.validateSignatures = validateSignatures;
        this.healthcheck = healthcheck;
    }

    @Override
    public void run(T configuration, Environment environment) throws Exception {
        configExtractor.getMetadataConfiguration(configuration).ifPresent(mc -> {
            metadataResolver = dropwizardMetadataResolverFactory.createMetadataResolver(environment, mc, validateSignatures);
            try {
                signatureTrustEngine = metadataSignatureTrustEngineFactory.createSignatureTrustEngine(metadataResolver);
                credentialResolver = credentialResolverFactory.create(metadataResolver);
            } catch (ComponentInitializationException e) {
                throw new MetadataResolverCreationException(mc.getUri(), e.getMessage());
            }

            if (healthcheck) {
                registerMetadataHealthcheck(environment, mc);
            }
        });
    }

    private void registerMetadataHealthcheck(Environment environment, MetadataResolverConfiguration mc) {
        MetadataHealthCheck healthCheck = new MetadataHealthCheck(
                metadataResolver,
                mc.getExpectedEntityId()
        );
        environment.healthChecks().register(mc.getUri().toString(), healthCheck);
    }

    @Override
    public void initialize(Bootstrap<?> bootstrap) {
        //NOOP
    }

    @Nullable
    public MetadataResolver getMetadataResolver() {
        return metadataResolver;
    }

    public Provider<MetadataResolver> getMetadataResolverProvider() {
        return () -> metadataResolver;
    }

    @Nullable
    public ExplicitKeySignatureTrustEngine getSignatureTrustEngine() {
        return signatureTrustEngine;
    }

    public Provider<ExplicitKeySignatureTrustEngine> getSignatureTrustEngineProvider() {
        return () -> signatureTrustEngine;
    }

    @Nullable
    public MetadataCredentialResolver getMetadataCredentialResolver() {
        return credentialResolver;
    }

    public Provider<MetadataCredentialResolver> getMetadataCredentialResolverProvider() {
        return () -> credentialResolver;
    }


    public Module getMetadataModule() {
      return binder -> binder.bind(MetadataResolver.class).toProvider(getMetadataResolverProvider());
    }

    public interface MetadataConfigurationExtractor<T> {
        Optional<MetadataResolverConfiguration> getMetadataConfiguration(T configuration);
    }

    public static class Builder<T> {

        private final MetadataConfigurationExtractor<T> configExtractor;
        private MetadataSignatureTrustEngineFactory metadataSignatureTrustEngineFactory;
        private CredentialResolverFactory credentialResolverFactory;
        private DropwizardMetadataResolverFactory dropwizardMetadataResolverFactory;
        private boolean validateSignatures;
        private boolean healthcheck;

        public Builder(MetadataConfigurationExtractor<T> configExtractor) {
            this.configExtractor = configExtractor;
            this.metadataSignatureTrustEngineFactory = new MetadataSignatureTrustEngineFactory();
            this.credentialResolverFactory = new CredentialResolverFactory();
            this.dropwizardMetadataResolverFactory = new DropwizardMetadataResolverFactory();
            this.validateSignatures = true;
            this.healthcheck = true;
        }

        public Builder<T> withMetadataSignatureTrustEngineFactory(MetadataSignatureTrustEngineFactory factory) {
            this.metadataSignatureTrustEngineFactory = factory;
            return this;
        }

        public Builder<T> withCredentialResolverFactory(CredentialResolverFactory factory) {
            this.credentialResolverFactory = factory;
            return this;
        }

        public Builder<T> withDropwizardMetadataResolverFactory(DropwizardMetadataResolverFactory factory) {
            this.dropwizardMetadataResolverFactory = factory;
            return this;
        }

        public Builder<T> withValidateSignatures(boolean validateSignatures) {
            this.validateSignatures = validateSignatures;
            return this;
        }

        public Builder<T> withHealthcheck(boolean healthcheck) {
            this.healthcheck = healthcheck;
            return this;
        }

        public MetadataResolverBundle build() {
            return new MetadataResolverBundle(
                    configExtractor,
                    metadataSignatureTrustEngineFactory,
                    credentialResolverFactory,
                    dropwizardMetadataResolverFactory,
                    validateSignatures,
                    healthcheck);
        }
    }

}
