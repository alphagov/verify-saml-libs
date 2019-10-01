package uk.gov.ida.saml.core.validators.conditions;

import com.google.common.collect.ImmutableList;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Answers;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.impl.AudienceBuilder;
import uk.gov.ida.saml.core.IdaSamlBootstrap;
import uk.gov.ida.saml.core.validation.SamlResponseValidationException;
import uk.gov.ida.saml.core.validation.conditions.AudienceRestrictionValidator;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.ida.saml.core.test.builders.AudienceRestrictionBuilder.anAudienceRestriction;

public class AudienceRestrictionValidatorTest {

    private AudienceRestrictionValidator validator;

    @Before
    public void setUp() {
        validator = new AudienceRestrictionValidator();
        IdaSamlBootstrap.bootstrap();
    }

    @Test
    public void shouldNotComplainWhenCorrectDataIsPassed() {
        Audience audience = new AudienceBuilder().buildObject();
        audience.setAudienceURI("some-entity-id");

        AudienceRestriction audienceRestriction = mock(AudienceRestriction.class, Answers.RETURNS_DEEP_STUBS);
        when(audienceRestriction.getAudiences()).thenReturn(ImmutableList.of(audience));

        validator.validate(ImmutableList.of(audienceRestriction), "some-entity-id");
    }

    @Test
    public void shouldThrowExceptionWhenAudienceRestrictionsIsNull() {
        List<AudienceRestriction> audienceRestrictions = null;

        assertThatThrownBy(() -> {
                validator.validate(audienceRestrictions, "any-entity-id");
            })
            .isInstanceOf(SamlResponseValidationException.class)
            .hasMessageContaining("Exactly one audience restriction is expected.");
    }

    @Test
    public void shouldThrowExceptionWhenAudienceRestrictionsHasMoreThanOneElements() {
        List<AudienceRestriction> audienceRestrictions = ImmutableList.of(
            anAudienceRestriction().build(),
            anAudienceRestriction().build()
        );

        assertThatThrownBy(() -> {
                validator.validate(audienceRestrictions, "any-entity-id");
            })
            .isInstanceOf(SamlResponseValidationException.class)
            .hasMessageContaining("Exactly one audience restriction is expected.");
    }

    @Test
    public void shouldThrowExceptionWhenAudiencesIsNull() {
        AudienceRestriction audienceRestriction = mock(AudienceRestriction.class, Answers.RETURNS_DEEP_STUBS);
        when(audienceRestriction.getAudiences()).thenReturn(null);

        assertThatThrownBy(() -> {
                validator.validate(ImmutableList.of(audienceRestriction), "any-entity-id");
            })
            .isInstanceOf(SamlResponseValidationException.class)
            .hasMessageContaining("Exactly one audience is expected.");
    }

    @Test
    public void shouldThrowExceptionWhenAudiencesIsMoreThanOne() {
        AudienceRestriction audienceRestriction = anAudienceRestriction().build();
        audienceRestriction.getAudiences().add(new AudienceBuilder().buildObject());
        audienceRestriction.getAudiences().add(new AudienceBuilder().buildObject());

        assertThatThrownBy(() -> {
                validator.validate(ImmutableList.of(audienceRestriction), "any-entity-id");
            })
            .isInstanceOf(SamlResponseValidationException.class)
            .hasMessageContaining("Exactly one audience is expected.");
    }

    @Test
    public void shouldThrowExceptionWhenAudienceUriDoesNotMatchTheEntityId() {
        Audience audience = new AudienceBuilder().buildObject();
        audience.setAudienceURI("some-entity-id");

        AudienceRestriction audienceRestriction = mock(AudienceRestriction.class, Answers.RETURNS_DEEP_STUBS);
        when(audienceRestriction.getAudiences()).thenReturn(ImmutableList.of(audience));

        assertThatThrownBy(() -> {
                validator.validate(ImmutableList.of(audienceRestriction), "unknown-entity-id");
            })
        .isInstanceOf(SamlResponseValidationException.class)
        .hasMessageContaining(String.format(
            "Audience must match an acceptable entity ID. Acceptable entity IDs are: %s but audience was: %s",
            "unknown-entity-id",
            "some-entity-id"));
    }
}