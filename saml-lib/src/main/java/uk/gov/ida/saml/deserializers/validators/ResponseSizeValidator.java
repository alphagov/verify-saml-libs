package uk.gov.ida.saml.deserializers.validators;

import com.google.inject.Inject;
import uk.gov.ida.saml.hub.validators.StringSizeValidator;

import java.util.Objects;

public class ResponseSizeValidator implements SizeValidator {
    // Ensures someone doing nasty things cannot get loads of data out of core hub in a single response

    protected static final int LOWER_BOUND = 1400;
    protected static final int UPPER_BOUND = 50000;

    private final StringSizeValidator validator;

    @Inject
    public ResponseSizeValidator() {
        this.validator = new StringSizeValidator();
    }

    @Override
    public void validate(String input) {
        validator.validate(Objects.requireNonNull(input, "input for response size validation cannot be null"), getLowerBound(), getUpperBound());
    }

    private int getUpperBound() {
        return UPPER_BOUND;
    }

    protected int getLowerBound() {
        return LOWER_BOUND;
    }
}
