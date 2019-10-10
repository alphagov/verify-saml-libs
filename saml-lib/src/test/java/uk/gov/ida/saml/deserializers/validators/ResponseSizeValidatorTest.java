package uk.gov.ida.saml.deserializers.validators;

import org.junit.Test;
import uk.gov.ida.saml.core.validation.SamlTransformationErrorException;

import java.util.Arrays;

import static uk.gov.ida.saml.deserializers.validators.ResponseSizeValidator.LOWER_BOUND;
import static uk.gov.ida.saml.deserializers.validators.ResponseSizeValidator.UPPER_BOUND;

public class ResponseSizeValidatorTest {

    @Test(expected = NullPointerException.class)
    public void shouldThrowNullPointerExceptionWhenInputNull() {
        new ResponseSizeValidator().validate(null);
    }

    @Test(expected = SamlTransformationErrorException.class)
    public void shouldThrowSamlTransformationErrorExceptionWhenInputTooSmall() {
        new ResponseSizeValidator().validate(createString(LOWER_BOUND - 1));
    }

    @Test(expected = SamlTransformationErrorException.class)
    public void shouldThrowSamlTransformationErrorExceptionWhenInputTooLarge() {
        new ResponseSizeValidator().validate(createString(UPPER_BOUND + 1));
    }

    @Test
    public void shouldThrowNoExceptionWhenResponseSizeOnBoundry() {
        new ResponseSizeValidator().validate(createString(LOWER_BOUND));
        new ResponseSizeValidator().validate(createString(UPPER_BOUND));
    }

    private String createString(int length) {
        char[] charArray = new char[length];
        Arrays.fill(charArray, 'a');
        return new String(charArray);
    }


}