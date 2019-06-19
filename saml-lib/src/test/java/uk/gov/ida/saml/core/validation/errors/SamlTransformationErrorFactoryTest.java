package uk.gov.ida.saml.core.validation.errors;

import org.junit.Test;
import org.slf4j.event.Level;
import uk.gov.ida.saml.core.errors.SamlTransformationErrorFactory;
import uk.gov.ida.saml.core.validation.SamlValidationSpecificationFailure;

import static org.assertj.core.api.Assertions.assertThat;

public class SamlTransformationErrorFactoryTest {
    @Test
    public void shouldHaveLevelWarnForDuplicateMatchingDataset() {
        SamlValidationSpecificationFailure failure =
                SamlTransformationErrorFactory.duplicateMatchingDataset("id", "responseIssuerId");
        assertThat(failure.getLogLevel()).isEqualTo(Level.WARN);

    }
    @Test // arbitrary choice of error
    public void shouldHaveLevelErrorForMissingIssueInstant() {
        SamlValidationSpecificationFailure failure =
                SamlTransformationErrorFactory.missingIssueInstant("id");
        assertThat(failure.getLogLevel()).isEqualTo(Level.ERROR);

    }

}
