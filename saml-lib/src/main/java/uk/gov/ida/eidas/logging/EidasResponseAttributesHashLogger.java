package uk.gov.ida.eidas.logging;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.google.common.collect.Lists;
import org.apache.commons.codec.binary.Hex;
import org.opensaml.security.crypto.JCAConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.List;

public class EidasResponseAttributesHashLogger {

    public static final String MDC_KEY_EIDAS_REQUEST_ID = "hubRequestId";
    public static final String MDC_KEY_EIDAS_DESTINATION = "destination";
    public static final String MDC_KEY_EIDAS_USER_HASH = "eidasUserHash";
    private Logger log = LoggerFactory.getLogger(EidasResponseAttributesHashLogger.class);

    private transient final ResponseAttributes responseAttributes;
    private final ObjectMapper objectMapper;

    private EidasResponseAttributesHashLogger() {
        responseAttributes = new ResponseAttributes();
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
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

    public void setDateOfBirth(LocalDate dateOfBirth) {
        this.responseAttributes.setDateOfBirth(dateOfBirth);
    }

    public void logHashFor(String requestId, String destination) {
        try {
            MDC.put(MDC_KEY_EIDAS_REQUEST_ID, requestId);
            MDC.put(MDC_KEY_EIDAS_DESTINATION, destination);
            MDC.put(MDC_KEY_EIDAS_USER_HASH, buildHash());
            log.info("Hash of eIDAS user attributes");
        } finally {
            MDC.remove(MDC_KEY_EIDAS_REQUEST_ID);
            MDC.remove(MDC_KEY_EIDAS_DESTINATION);
            MDC.remove(MDC_KEY_EIDAS_USER_HASH);
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
