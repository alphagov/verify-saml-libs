package uk.gov.ida.saml.hub.factories;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import uk.gov.ida.saml.core.domain.AuthnContext;
import uk.gov.ida.saml.core.domain.PersistentId;

import java.util.Arrays;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static uk.gov.ida.saml.core.test.builders.PersistentIdBuilder.aPersistentId;

@RunWith(MockitoJUnitRunner.class)
public class UserIdHashFactoryTest {

    private static final String HASHING_ENTITY_ID = "entity";
    private static final UserIdHashFactory USER_ID_HASH_FACTORY = new UserIdHashFactory(HASHING_ENTITY_ID);

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldPerformHashing() {
        final PersistentId persistentId = aPersistentId().build();
        final String issuerId = "partner";

        final String hashedId = USER_ID_HASH_FACTORY.hashId(issuerId, persistentId.getNameId(), Optional.of(AuthnContext.LEVEL_2));

        assertThat(hashedId).isEqualTo("a5fbea969c3837a712cbe9e188804796828f369106478e623a436fa07e8fd298");
    }

    @Test
    public void shouldGenerateADifferentHashForEveryLevelOfAssurance() {
        final PersistentId persistentId = aPersistentId().build();
        final String partnerEntityId = "partner";

        final long numberOfUniqueGeneratedHashedPids = Arrays.stream(AuthnContext.values())
                .map(authnContext -> USER_ID_HASH_FACTORY.hashId(partnerEntityId, persistentId.getNameId(), Optional.of(authnContext)))
                .distinct()
                .count();

        assertThat(numberOfUniqueGeneratedHashedPids).isEqualTo(5);
    }

    @Test
    public void shouldThrowErrorWhenAuthnContextAbsent() {
        exception.expect(UserIdHashFactory.AuthnContextMissingException.class);
        exception.expectMessage(String.format("Authn context absent for persistent id %s", "pid"));

        USER_ID_HASH_FACTORY.hashId("", "pid", Optional.empty());
    }
}
