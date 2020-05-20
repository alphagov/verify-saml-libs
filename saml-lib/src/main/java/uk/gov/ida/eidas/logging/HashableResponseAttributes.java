package uk.gov.ida.eidas.logging;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.google.common.collect.Lists;

import java.io.Serializable;
import java.time.LocalDate;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonPropertyOrder(value = {"requestId", "firstName", "middleNames", "surnames", "dateOfBirth"})
final class HashableResponseAttributes implements Serializable {

    @JsonProperty
    private String requestId;

    @JsonProperty
    private String firstName;

    @JsonProperty
    private List<String> middleNames = Lists.newArrayList();

    @JsonProperty
    private List<String> surnames = Lists.newArrayList();

    @JsonProperty
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate dateOfBirth;

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public void addMiddleName(String middleName) {
        this.middleNames.add(middleName);
    }

    public void addSurname(String surname) {
        this.surnames.add(surname);
    }

    public void setDateOfBirth(LocalDate dateOfBirth) {
        this.dateOfBirth = dateOfBirth;
    }
}
