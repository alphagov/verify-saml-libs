package uk.gov.ida.saml.core.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDate;

@JsonIgnoreProperties(ignoreUnknown = true)
public class NonMatchingTransliterableAttribute extends NonMatchingVerifiableAttribute<String> {

    @JsonProperty("nonLatinScriptValue")
    @JsonInclude(value = JsonInclude.Include.NON_NULL)
    private final String nonLatinScriptValue;

    @JsonCreator
    public NonMatchingTransliterableAttribute(
            @JsonProperty("value") String value,
            @JsonProperty("nonLatinScriptValue") @JsonInclude(value = JsonInclude.Include.NON_NULL) String nonLatinScriptValue,
            @JsonProperty("verified") boolean verified,
            @JsonProperty("from") @JsonInclude(JsonInclude.Include.NON_NULL) LocalDate from,
            @JsonProperty("to") @JsonInclude(JsonInclude.Include.NON_NULL) LocalDate to) {
        super(value, verified, from, to);
        this.nonLatinScriptValue = nonLatinScriptValue;
    }

    public String getNonLatinScriptValue() {
        return nonLatinScriptValue;
    }
}
