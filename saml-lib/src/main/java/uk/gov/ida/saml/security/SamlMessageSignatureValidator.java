package uk.gov.ida.saml.security;

import com.google.common.base.Strings;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.saml.core.validation.SamlValidationResponse;
import uk.gov.ida.saml.security.errors.SamlTransformationErrorFactory;
import uk.gov.ida.saml.security.validators.signature.SamlSignatureUtil;

import javax.xml.namespace.QName;

import java.util.Optional;

import static uk.gov.ida.saml.security.errors.SamlTransformationErrorFactory.invalidMessageSignature;
import static uk.gov.ida.saml.security.errors.SamlTransformationErrorFactory.unableToValidateMessageSignature;

public class SamlMessageSignatureValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SamlMessageSignatureValidator.class);
    private final SignatureValidator signatureValidator;


    public SamlMessageSignatureValidator(SignatureValidator signatureValidator) {
        this.signatureValidator = signatureValidator;
    }

    public SamlValidationResponse validate(Response response, QName role) {
        Issuer issuer = response.getIssuer();
        Optional<SamlValidationResponse> issuerResponse = validateIssuer(issuer);
        if (issuerResponse.isPresent()) return issuerResponse.get();
        return validateSignature(response, issuer.getValue(), role);
    }

    public SamlValidationResponse validate(Assertion assertion, QName role) {
        Issuer issuer = assertion.getIssuer();
        Optional<SamlValidationResponse> issuerResponse = validateIssuer(issuer);
        if (issuerResponse.isPresent()) return issuerResponse.get();
        return validateSignature(assertion, issuer.getValue(), role);
    }

    public SamlValidationResponse validateEidasAssertion(Assertion assertion, QName role) {
        Issuer issuer = assertion.getIssuer();
        Optional<SamlValidationResponse> issuerResponse = validateIssuer(issuer);
        if (issuerResponse.isPresent()) return issuerResponse.get();

        if (assertion.getSignature() == null) return SamlValidationResponse.aValidResponse();
        return validateSignature(assertion, issuer.getValue(), role);
    }

    /**
     * @param request - an AttributeQuery or AuthnRequest to validate
     * @param role - a QName role
     * @return a SamlValidationResponse indicating if the signature was valid
     */
    public SamlValidationResponse validate(RequestAbstractType request, QName role) {
        Issuer issuer = request.getIssuer();
        Optional<SamlValidationResponse> issuerResponse = validateIssuer(issuer);
        if (issuerResponse.isPresent()) return issuerResponse.get();
        return validateSignature(request, issuer.getValue(), role);
    }

    private Optional<SamlValidationResponse> validateIssuer(Issuer issuer) {
        if (issuer == null) {
            return Optional.of(SamlValidationResponse.anInvalidResponse(SamlTransformationErrorFactory.missingIssuer()));
        }
        if (Strings.isNullOrEmpty(issuer.getValue())) {
            return Optional.of(SamlValidationResponse.anInvalidResponse(SamlTransformationErrorFactory.emptyIssuer()));
        }
        return Optional.empty();
    }

    private SamlValidationResponse validateSignature(SignableSAMLObject signableSAMLObject, String issuerId, QName role) {
        if (signableSAMLObject.getSignature() == null){
            return SamlValidationResponse.anInvalidResponse(SamlTransformationErrorFactory.missingSignature());
        }
        if (!SamlSignatureUtil.isSignaturePresent(signableSAMLObject.getSignature())) {
            return SamlValidationResponse.anInvalidResponse(SamlTransformationErrorFactory.signatureNotSigned());
        }
        try {
            if (signatureValidator.validate(signableSAMLObject, issuerId, role)) {
                return SamlValidationResponse.aValidResponse();
            }
            else {
                return SamlValidationResponse.anInvalidResponse(invalidMessageSignature());
            }

        } catch (org.opensaml.security.SecurityException e) {
            LOG.warn("There was an unexpected error validating the message signature using the provided certificate.", e);
            return SamlValidationResponse.anInvalidResponse(unableToValidateMessageSignature(), e);
        } catch (SignatureException e) {
            LOG.error("XML Signature invalid (SAML core section 5.4)", e);
            return SamlValidationResponse.anInvalidResponse(unableToValidateMessageSignature(), e);
        }
    }

}
