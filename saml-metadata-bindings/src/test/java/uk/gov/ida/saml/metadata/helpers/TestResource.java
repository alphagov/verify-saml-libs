package uk.gov.ida.saml.metadata.helpers;


import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import uk.gov.ida.saml.core.test.TestEntityIds;

import javax.ws.rs.GET;
import javax.ws.rs.Path;

@Path("/")
public class TestResource {
    private MetadataResolver metadataResolver;
    TestResource(MetadataResolver metadataResolver) {
        this.metadataResolver = metadataResolver;
    }

    @Path("/foo")
    @GET
    public String getMetadata() throws ResolverException {
        return metadataResolver.resolveSingle(new CriteriaSet(new EntityIdCriterion(TestEntityIds.HUB_ENTITY_ID))).getEntityID();
    };
}
