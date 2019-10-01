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

import static junit.framework.TestCase.fail;
import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(OpenSAMLMockitoRunner.class)
public class AudienceRestrictionValidatorMultipleEntityIdTests {

    private AudienceRestrictionValidator validator;

    @Before
    public void setup() {
        validator = new AudienceRestrictionValidator();
    }

    @Test
    public void audienceRestrictionValidatorShouldAcceptOnlyOneAudienceRestriction() {
        List<AudienceRestriction> restrictions = new LinkedList<>();
        String[] acceptableAudiences = new String[] { "audience1", "audience2" };

        restrictions.add(AudienceRestrictionBuilder.anAudienceRestriction().withAudienceId("audience1").build());

        try {
            validator.validate(restrictions, acceptableAudiences);
        } catch (Exception e) {
            fail("Should not fail validation with a single audience restriction.");
        }

        restrictions.add(AudienceRestrictionBuilder.anAudienceRestriction().withAudienceId("audience2").build());

        try {
            validator.validate(restrictions, acceptableAudiences);
            fail("Should not pass validation with more than 1 audience restriction.");
        } catch (SamlResponseValidationException e) {
            assertEquals(e.getMessage(), "Exactly one audience restriction is expected.");
        }
    }

    @Test
    public void audienceRestrictionValidatorShouldMatchOnAcceptableEntityIds() {
        List<AudienceRestriction> restrictions = new LinkedList<>();
        String[] acceptableAudiences = new String[] { "audience1", "audience2" };
        String[] unacceptableAudiences = new String[] { "audience2" };

        restrictions.add(AudienceRestrictionBuilder.anAudienceRestriction().withAudienceId("audience1").build());

        try {
            validator.validate(restrictions, unacceptableAudiences);
            fail("Should not pass validation when the audience is not found amongst the restrictions.");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("Audience must match an acceptable entity ID."));
        }

        try {
            validator.validate(restrictions, acceptableAudiences);
        } catch (SamlResponseValidationException e) {
            fail("Should pass validation when the audience is found amongst the restrictions.");
        }
    }

}

