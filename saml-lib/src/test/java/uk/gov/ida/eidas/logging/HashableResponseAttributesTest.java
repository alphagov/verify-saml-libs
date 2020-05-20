package uk.gov.ida.eidas.logging;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.Test;

import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;

public class HashableResponseAttributesTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    static {
        OBJECT_MAPPER.registerModule(new JavaTimeModule());
    }

    @Test
    public void shouldBeSerialisedToStringCorrectly() throws JsonProcessingException {
        final HashableResponseAttributes responseAttributes = new HashableResponseAttributes();
        LocalDate dateOfBirth = LocalDate.of(2019, 3, 24);
        responseAttributes.setRequestId("a");
        responseAttributes.setFirstName("fn");
        responseAttributes.addMiddleName("m1");
        responseAttributes.addMiddleName("mn2");
        responseAttributes.addSurname("sn");
        responseAttributes.setDateOfBirth(dateOfBirth);

        final String attributesString = OBJECT_MAPPER.writeValueAsString(responseAttributes);
        final String expectedAttributesString = "{\"requestId\":\"a\",\"firstName\":\"fn\",\"middleNames\":[\"m1\",\"mn2\"],\"surnames\":[\"sn\"],\"dateOfBirth\":\"2019-03-24\"}";

        assertThat(attributesString).isEqualTo(expectedAttributesString);
    }

    @Test
    public void shouldBeSerialisedToStringCorrectlyWithMinimumAttributeSet() throws JsonProcessingException {
        final HashableResponseAttributes responseAttributes = new HashableResponseAttributes();
        responseAttributes.setRequestId("a");
        responseAttributes.setFirstName("fn");
        responseAttributes.addSurname("sn");

        final String attributesString = OBJECT_MAPPER.writeValueAsString(responseAttributes);
        final String expectedAttributesString = "{\"requestId\":\"a\",\"firstName\":\"fn\",\"surnames\":[\"sn\"]}";

        assertThat(attributesString).isEqualTo(expectedAttributesString);
    }
}
