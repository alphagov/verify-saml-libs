package uk.gov.ida.saml.core.validation.assertion;

import org.junit.Test;
import org.opensaml.saml.saml2.core.Assertion;

import static org.junit.Assert.fail;

public class ExceptionThrowingValidatorTest {

    @Test(expected = ExceptionThrowingValidator.ValidationException.class)
    public void shouldCatchValidationException() throws ExceptionThrowingValidator.ValidationException {
        ExceptionThrowingValidator<Assertion> validator = e -> {
            throw new ExceptionThrowingValidator.ValidationException("", new RuntimeException(""));
        };
        validator.apply(null);
    }

    @Test(expected = RuntimeException.class)
    public void shouldPropagateARuntimeExceptionOutsideLambdaIfNotCaughtInLambda() {
        ExceptionThrowingValidator<Assertion> validator = e -> {
            throw new RuntimeException();
        };
        try {
            validator.apply(null);
        } catch (ExceptionThrowingValidator.ValidationException e) {
            fail();
        }

    }
}
