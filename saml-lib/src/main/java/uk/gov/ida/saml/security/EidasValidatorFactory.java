package uk.gov.ida.saml.security;

import com.google.inject.Inject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.slf4j.event.Level;
import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;
import uk.gov.ida.saml.metadata.MetadataResolverRepository;
import uk.gov.ida.saml.security.validators.ValidatedResponse;
import uk.gov.ida.saml.security.validators.signature.SamlResponseSignatureValidator;

import java.util.List;

import static java.text.MessageFormat.format;

public class EidasValidatorFactory {

    private MetadataResolverRepository eidasMetadataResolverRepository;

    @Inject
    public EidasValidatorFactory(MetadataResolverRepository eidasMetadataResolverRepository) {
        this.eidasMetadataResolverRepository = eidasMetadataResolverRepository;
    }

    public ValidatedResponse getValidatedResponse(Response response) {
        SamlResponseSignatureValidator samlResponseSignatureValidator = new SamlResponseSignatureValidator(getSamlMessageSignatureValidator(response.getIssuer().getValue()));
        return samlResponseSignatureValidator.validate(response, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
    }

    public void getValidatedAssertion(ValidatedResponse validatedResponse, List<Assertion> decryptedAssertions) {
        SamlAssertionsSignatureValidator samlAssertionsSignatureValidator = new SamlAssertionsSignatureValidator(getSamlMessageSignatureValidator(validatedResponse.getIssuer().getValue()));
        samlAssertionsSignatureValidator.validateEidas(decryptedAssertions, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
    }

    private SamlMessageSignatureValidator getSamlMessageSignatureValidator(String entityId) {
        return eidasMetadataResolverRepository
                .getSignatureTrustEngine(entityId)
                .map(MetadataBackedSignatureValidator::withoutCertificateChainValidation)
                .map(SamlMessageSignatureValidator::new)
                .orElseThrow(() -> new SamlTransformationErrorException(format("Unable to find metadata resolver for entity Id {0}", entityId), Level.ERROR));
    }

}
