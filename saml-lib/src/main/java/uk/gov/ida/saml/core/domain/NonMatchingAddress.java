package uk.gov.ida.saml.core.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Objects;

public class NonMatchingAddress {

    private final List<String> lines;
    private final String postCode;
    private final String internationalPostCode;
    private final String uprn;

    public NonMatchingAddress(
            @JsonProperty("lines") List<String> lines,
            @JsonProperty("postCode") @JsonInclude(JsonInclude.Include.NON_NULL) String postCode,
            @JsonProperty("internationalPostCode") @JsonInclude(JsonInclude.Include.NON_NULL) String internationalPostCode,
            @JsonProperty("uprn") @JsonInclude(JsonInclude.Include.NON_NULL) String uprn) {
        this.lines = lines;
        this.postCode = postCode;
        this.internationalPostCode = internationalPostCode;
        this.uprn = uprn;
    }

    public List<String> getLines() {
        return lines;
    }

    public String getPostCode() {
        return postCode;
    }

    public String getInternationalPostCode() {
        return internationalPostCode;
    }

    public String getUprn() {
        return uprn;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        NonMatchingAddress other = (NonMatchingAddress) o;

        if (!Objects.equals(lines, other.lines)) return false;
        if (!Objects.equals(postCode, other.postCode)) return false;
        if (!Objects.equals(uprn, other.uprn)) return false;
        return (!Objects.equals(internationalPostCode, other.internationalPostCode));
    }

    @Override
    public int hashCode() {
        int result = lines != null ? lines.hashCode() : 0;
        result = 31 * result + (postCode != null ? postCode.hashCode() : 0);
        result = 31 * result + (internationalPostCode != null ? internationalPostCode.hashCode() : 0);
        result = 31 * result + (uprn != null ? uprn.hashCode() : 0);
        return result;
    }

    @Override
    public String toString() {
        return "Address{" +
                ", lines=" + lines +
                ", postCode='" + postCode + '\'' +
                ", internationalPostCode='" + internationalPostCode + '\'' +
                ", uprn='" + uprn + '\'' +
                '}';
    }
}
