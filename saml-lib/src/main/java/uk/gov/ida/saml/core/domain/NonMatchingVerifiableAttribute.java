package uk.gov.ida.saml.core.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDate;

@JsonIgnoreProperties(ignoreUnknown = true)
public class NonMatchingVerifiableAttribute<T> {

    private final T value;
    private final boolean verified;
    private final LocalDate from;
    private final LocalDate to;

    @JsonCreator
    public NonMatchingVerifiableAttribute(
            @JsonProperty("value") T value,
            @JsonProperty("verified") boolean verified,
            @JsonProperty("from") @JsonInclude(JsonInclude.Include.NON_NULL) LocalDate from,
            @JsonProperty("to") @JsonInclude(JsonInclude.Include.NON_NULL) LocalDate to) {
        this.value = value;
        this.verified = verified;
        this.from = from;
        this.to = to;
    }

    public T getValue() {
        return value;
    }

    public boolean isVerified() {
        return verified;
    }

    public boolean isValid() {
        return this.verified && this.isCurrent() && this.value != null;
    }

    public boolean isCurrent() {
        return (this.from == null || this.from.isBefore(LocalDate.now())) &&
                (this.to == null || this.to.isAfter(LocalDate.now()));
    }

    public LocalDate getFrom() {
        return from;
    }

    public LocalDate getTo() {
        return to;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        NonMatchingVerifiableAttribute<?> that = (NonMatchingVerifiableAttribute<?>) o;

        return isVerified() == that.isVerified() &&
                getValue().equals(that.getValue()) &&
                getFrom().equals(that.getFrom()) &&
                getTo().equals(that.getTo());
    }

    @Override
    public int hashCode() {
        int result = getValue().hashCode();
        result = 31 * result + (isVerified() ? 1 : 0);
        result = 31 * result + getFrom().hashCode();
        result = 31 * result + getTo().hashCode();
        return result;
    }

    @Override
    public String toString() {
        return String.format("NonMatchingVerifiableAttribute{ value=%s, verified=%s, from=%s, to=%s }", value, verified, from, to);
    }
}
