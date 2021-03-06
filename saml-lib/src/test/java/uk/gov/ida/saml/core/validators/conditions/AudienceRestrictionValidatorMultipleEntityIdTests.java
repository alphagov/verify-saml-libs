package uk.gov.ida.saml.core.validators.conditions;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import uk.gov.ida.saml.core.test.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.core.test.builders.AudienceRestrictionBuilder;
import uk.gov.ida.saml.core.validation.SamlResponseValidationException;
import uk.gov.ida.saml.core.validation.conditions.AudienceRestrictionValidator;

import java.util.LinkedList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

@RunWith(OpenSAMLMockitoRunner.class)
public class AudienceRestrictionValidatorMultipleEntityIdTests {

    private AudienceRestrictionValidator validator;

    @Before
    public void setUp() {
        validator = new AudienceRestrictionValidator();
    }

    @Test
    public void audienceRestrictionValidatorShouldAcceptOneAudienceRestriction() {
        String[] acceptableAudiences = new String[]{"audience1", "audience2"};
        List<AudienceRestriction> restrictions = new LinkedList<>();
        restrictions.add(AudienceRestrictionBuilder.anAudienceRestriction().withAudienceId("audience1").build());

        validator.validate(restrictions, acceptableAudiences);
    }

    @Test
    public void audienceRestrictionValidatorShouldRejectMoreThanOneAudienceRestriction() {
        String[] acceptableAudiences = new String[]{ "audience1", "audience2" };
        List<AudienceRestriction> restrictions = new LinkedList<>();
        restrictions.add(AudienceRestrictionBuilder.anAudienceRestriction().withAudienceId("audience1").build());
        restrictions.add(AudienceRestrictionBuilder.anAudienceRestriction().withAudienceId("audience2").build());

        assertThatThrownBy(() -> {
                validator.validate(restrictions, acceptableAudiences);
            })
            .isInstanceOf(SamlResponseValidationException.class)
            .hasMessageContaining("Exactly one audience restriction is expected.");
    }

    @Test
    public void audienceRestrictionValidatorShouldRejectUnacceptableEntityIds() {
        String[] unacceptableAudiences = new String[]{ "audience2" };
        List<AudienceRestriction> restrictions = new LinkedList<>();
        restrictions.add(AudienceRestrictionBuilder.anAudienceRestriction().withAudienceId("audience1").build());

        assertThatThrownBy(() -> {
                validator.validate(restrictions, unacceptableAudiences);
            })
            .isInstanceOf(SamlResponseValidationException.class)
            .hasMessageContaining("Audience must match an acceptable entity ID.");
    }

    @Test
    public void audienceRestrictionValidatorShouldMatchOnAcceptableEntityIds() {
        List<AudienceRestriction> restrictions = new LinkedList<>();
        restrictions.add(AudienceRestrictionBuilder.anAudienceRestriction().withAudienceId("audience1").build());
        String[] acceptableAudiences = new String[] { "audience1", "audience2" };
        validator.validate(restrictions, acceptableAudiences);
    }

}

