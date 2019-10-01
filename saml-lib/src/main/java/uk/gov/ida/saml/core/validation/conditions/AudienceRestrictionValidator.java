package uk.gov.ida.saml.core.validation.conditions;

import com.google.inject.Inject;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import uk.gov.ida.saml.core.validation.SamlResponseValidationException;

import java.util.Arrays;
import java.util.List;

public class AudienceRestrictionValidator {
    @Inject
    public AudienceRestrictionValidator() {
    }

    public void validate(List<AudienceRestriction> audienceRestrictions, String... acceptableEntityIds) {
        if (audienceRestrictions == null || audienceRestrictions.size() != 1) {
            throw new SamlResponseValidationException("Exactly one audience restriction is expected.");
        }

        List<Audience> audiences = audienceRestrictions.get(0).getAudiences();
        if (audiences == null || audiences.size() != 1) {
            throw new SamlResponseValidationException("Exactly one audience is expected.");
        }

        String audience = audiences.get(0).getAudienceURI();
        if (Arrays.stream(acceptableEntityIds).noneMatch(s -> s.equals(audience))) {
            throw new SamlResponseValidationException(String.format(
                "Audience must match an acceptable entity ID. Acceptable entity IDs are: %s but audience was: %s",
                StringUtils.join(acceptableEntityIds, ", "),
                audience));
        }
    }
}
