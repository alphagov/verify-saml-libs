package uk.gov.ida.saml.security.exception;

import org.slf4j.event.Level;
import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;
import uk.gov.ida.saml.core.validation.SamlValidationSpecificationFailure;

public class SamlFailedToEncryptException extends SamlTransformationErrorException {

    public SamlFailedToEncryptException(String errorMessage, Exception cause, Level logLevel) {
        super(errorMessage, cause, logLevel);
    }

    public SamlFailedToEncryptException(String errorMessage, Level logLevel) {
        super(errorMessage, logLevel);
    }

    public SamlFailedToEncryptException(SamlValidationSpecificationFailure failure, Exception cause) {
        super(failure.getErrorMessage(), cause, failure.getLogLevel());
    }
}
