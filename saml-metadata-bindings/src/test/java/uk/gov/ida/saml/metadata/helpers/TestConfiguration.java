package uk.gov.ida.saml.metadata.helpers;


import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.Configuration;
import uk.gov.ida.saml.metadata.MetadataResolverConfiguration;
import uk.gov.ida.saml.metadata.MultiTrustStoresBackedMetadataConfiguration;

public class TestConfiguration extends Configuration {
    @JsonProperty("metadata")
    private MultiTrustStoresBackedMetadataConfiguration metadataConfiguration;

    public MetadataResolverConfiguration getMetadataConfiguration() {
        return metadataConfiguration;
    }
}
