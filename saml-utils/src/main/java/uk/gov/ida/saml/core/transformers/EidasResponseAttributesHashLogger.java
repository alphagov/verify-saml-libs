package uk.gov.ida.saml.core.transformers;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import com.google.common.collect.Lists;
import org.apache.commons.codec.binary.Hex;
import org.joda.time.DateTime;
import org.joda.time.LocalDate;
import org.opensaml.security.crypto.JCAConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public final class EidasResponseAttributesHashLogger {

    private Logger log = LoggerFactory.getLogger(EidasResponseAttributesHashLogger.class);

    private transient final ResponseAttributes responseAttributes;
    private final ObjectMapper objectMapper;

    private EidasResponseAttributesHashLogger() {
        responseAttributes = new ResponseAttributes();
        objectMapper = new ObjectMapper();
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        objectMapper.registerModule(new JodaModule());
    }

    public static EidasResponseAttributesHashLogger instance() {
        return new EidasResponseAttributesHashLogger();
    }

    public void setPid(String pid) {
        responseAttributes.setPid(pid);
    }

    public void setFirstName(String firstName) {
        responseAttributes.setFirstName(firstName);
    }

    public void addMiddleName(String middleName) {
        this.responseAttributes.addMiddleName(middleName);
    }

    public void addSurname(String surname) {
        this.responseAttributes.addSurname(surname);
    }

    public void setDateOfBirth(DateTime dateOfBirth) {
        this.responseAttributes.setDateOfBirth(dateOfBirth.toLocalDate());
    }

    public void logHashFor(String requestId, String destination) {
        try {
            MDC.put("eidasRequestId", requestId);
            MDC.put("eidasDestination", destination);
            MDC.put("eidasUserHash", buildHash());
            log.info("Hash of eIDAS user attributes");
        } finally {
            MDC.clear();
        }
    }

    private String buildHash() {
        try {
            return hashFor(objectMapper.writeValueAsString(responseAttributes));
        } catch (NoSuchAlgorithmException | JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    private String hashFor(String toHash) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(JCAConstants.DIGEST_SHA256);
        return Hex.encodeHexString(md.digest(toHash.getBytes(StandardCharsets.UTF_8)));
    }

    @JsonPropertyOrder(value = {"pid", "firstName", "middleNames", "surnames", "dateOfBirth"})
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private final static class ResponseAttributes implements Serializable {

        @JsonProperty
        private String pid;

        @JsonProperty
        private String firstName;

        @JsonProperty
        private List<String> middleNames = Lists.newArrayList();

        @JsonProperty
        private List<String> surnames = Lists.newArrayList();

        @JsonProperty
        @JsonFormat(pattern = "yyyy-MM-dd")
        private LocalDate dateOfBirth;

        public void setPid(String pid) {
            this.pid = pid;
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
}
