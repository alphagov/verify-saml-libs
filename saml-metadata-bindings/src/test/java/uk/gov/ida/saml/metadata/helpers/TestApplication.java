package uk.gov.ida.saml.metadata.helpers;

import io.dropwizard.Application;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import uk.gov.ida.saml.metadata.bundle.MetadataResolverBundle;

public class TestApplication extends Application<TestConfiguration> {
    private MetadataResolverBundle<TestConfiguration> bundle;

    @Override
    public void initialize(Bootstrap<TestConfiguration> bootstrap) {
        super.initialize(bootstrap);
        bundle = new MetadataResolverBundle<>(TestConfiguration::getMetadataConfiguration);
        bootstrap.addBundle(bundle);
    }

    @Override
    public void run(TestConfiguration configuration, Environment environment) {
        environment.jersey().register(new TestResource(bundle.getMetadataResolver()));
    }
}
