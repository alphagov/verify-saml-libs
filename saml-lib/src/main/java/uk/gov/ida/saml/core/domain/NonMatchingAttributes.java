package uk.gov.ida.saml.core.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.collections.CollectionUtils;

import java.time.LocalDate;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class NonMatchingAttributes {

    protected final List<NonMatchingTransliterableAttribute> firstNames;
    protected final List<NonMatchingVerifiableAttribute<String>> middleNames;
    protected final List<NonMatchingTransliterableAttribute> surnames;
    protected final List<NonMatchingVerifiableAttribute<LocalDate>> datesOfBirth;
    protected final NonMatchingVerifiableAttribute<Gender> gender;
    protected final List<NonMatchingVerifiableAttribute<NonMatchingAddress>> addresses;

    @JsonCreator
    public NonMatchingAttributes(
            @JsonProperty("firstNames") List<NonMatchingTransliterableAttribute> firstNames,
            @JsonProperty("middleNames") List<NonMatchingVerifiableAttribute<String>> middleNames,
            @JsonProperty("surnames") List<NonMatchingTransliterableAttribute> surnames,
            @JsonProperty("datesOfBirth") List<NonMatchingVerifiableAttribute<LocalDate>> datesOfBirth,
            @JsonProperty("gender") NonMatchingVerifiableAttribute<Gender> gender,
            @JsonProperty("addresses") List<NonMatchingVerifiableAttribute<NonMatchingAddress>> addresses) {
        this.firstNames = firstNames;
        this.middleNames = middleNames;
        this.surnames = surnames;
        this.datesOfBirth = datesOfBirth;
        this.gender = gender;
        this.addresses = addresses;
    }

    public List<NonMatchingTransliterableAttribute> getFirstNames() {
        return firstNames;
    }

    public List<NonMatchingVerifiableAttribute<String>> getMiddleNames() {
        return middleNames;
    }

    public List<NonMatchingTransliterableAttribute> getSurnames() {
        return surnames;
    }

    public List<NonMatchingVerifiableAttribute<LocalDate>> getDatesOfBirth() {
        return datesOfBirth;
    }

    public NonMatchingVerifiableAttribute<Gender> getGender() {
        return gender;
    }

    public List<NonMatchingVerifiableAttribute<NonMatchingAddress>> getAddresses() {
        return addresses;
    }

    public static String combineAttributeValues(List<? extends NonMatchingVerifiableAttribute<String>> attributes) {
        return attributes.stream()
                .filter(Objects::nonNull)
                .map(NonMatchingVerifiableAttribute::getValue)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.joining(" "));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        NonMatchingAttributes that = (NonMatchingAttributes) o;
        if (!Objects.equals(firstNames, that.firstNames)) return false;

        if (middleNames != null ? !(that.middleNames != null && CollectionUtils.isEqualCollection(middleNames, that.middleNames)) : that.middleNames != null) {
            return false;
        }

        if (surnames != null ? !(that.surnames != null && CollectionUtils.isEqualCollection(surnames, that.surnames)) : that.surnames != null) {
            return false;
        }

        if (!Objects.equals(datesOfBirth, that.datesOfBirth)) return false;
        if (!Objects.equals(gender, that.gender)) return false;

        return (addresses != null ? !(that.addresses != null && CollectionUtils.isEqualCollection(addresses, that.addresses)) : that.addresses != null);
    }

    @Override
    public int hashCode() {
        int result = firstNames != null ? firstNames.hashCode() : 0;
        result = 31 * result + (middleNames != null ? middleNames.hashCode() : 0);
        result = 31 * result + (surnames != null ? surnames.hashCode() : 0);
        result = 31 * result + (datesOfBirth != null ? datesOfBirth.hashCode() : 0);
        result = 31 * result + (gender != null ? gender.hashCode() : 0);
        result = 31 * result + (addresses != null ? addresses.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return String.format(
                "Attributes{ firstNames=%s, middleNames=%s, surnames=%s, datesOfBirth=%s, gender=%s, addresses=%s}",
                firstNames, middleNames, surnames, datesOfBirth, gender, addresses);
    }
}
