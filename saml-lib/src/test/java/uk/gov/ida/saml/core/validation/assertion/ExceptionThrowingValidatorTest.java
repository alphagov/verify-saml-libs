package uk.gov.ida.saml.core.validation.assertion;

import org.junit.Test;
import org.opensaml.saml.saml2.core.Assertion;
import uk.gov.ida.saml.core.validation.SamlResponseValidationException;

import static org.junit.Assert.fail;

public class ExceptionThrowingValidatorTest {

    @Test(expected = ExceptionThrowingValidator.ValidationException.class)
    public void shouldCatchValidationException() throws ExceptionThrowingValidator.ValidationException {
        ExceptionThrowingValidator<Assertion> validator = e -> {
            throw new ExceptionThrowingValidator.ValidationException("message", new SamlResponseValidationException("message"));
        };
        validator.apply(null);
    }

    @Test(expected = RuntimeException.class)
    public void shouldPropagateARuntimeExceptionOutsideLambdaIfNotCaughtInLambda() {
        ExceptionThrowingValidator<Assertion> validator = e -> {
            throw new SamlResponseValidationException("message");
        };
        try {
            validator.apply(null);
        } catch (ExceptionThrowingValidator.ValidationException e) {
            fail();
        }

    }
}
