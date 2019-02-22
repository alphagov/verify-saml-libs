package uk.gov.ida.saml.core.transformers;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.junit.Assert.assertEquals;
import static uk.gov.ida.saml.core.transformers.ResponseAttributesHashFactory.hashResponseDetails;

public class ResponseAttributesHashFactoryTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldCreateHashOfResponseAttributes() {
        String hashedResponse = hashResponseDetails("pid", "jim", "bob", "joe", "1989-10-10");

        assertEquals("Hashes do not match up", hashedResponse, "437256f80cf561b2fa195bd1ed4293d4432d1c83090558bf3dd568c272943fd8");
    }

    @Test
    public void shouldThrowWhenDateFormatIsIncorrect() {
        exception.expect(RuntimeException.class);
        exception.expectMessage("Date does not match format YYYY-MM-DD");

        hashResponseDetails("pid", "jim", "bob", "joe", "10-10-1989");
    }
}
