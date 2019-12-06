package uk.gov.ida.eidas.logging;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.commons.codec.binary.Hex;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.crypto.JCAConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import uk.gov.ida.saml.core.domain.AddressFactory;
import uk.gov.ida.saml.core.domain.AuthnContext;
import uk.gov.ida.saml.core.domain.NonMatchingAttributes;
import uk.gov.ida.saml.core.domain.NonMatchingVerifiableAttribute;
import uk.gov.ida.saml.core.transformers.MatchingDatasetToNonMatchingAttributesMapper;
import uk.gov.ida.saml.core.transformers.VerifyMatchingDatasetUnmarshaller;
import uk.gov.ida.saml.hub.factories.UserIdHashFactory;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import static uk.gov.ida.saml.core.transformers.MatchingDatasetToNonMatchingAttributesMapper.attributeComparator;

public final class EidasAuthnResponseAttributesHashLogger {

    public static final String MDC_KEY_EIDAS_REQUEST_ID = "hubRequestId";
    public static final String MDC_KEY_EIDAS_DESTINATION = "destination";
    public static final String MDC_KEY_EIDAS_USER_HASH = "eidasUserHash";

    private static final VerifyMatchingDatasetUnmarshaller MATCHING_DATASET_UNMARSHALLER = new VerifyMatchingDatasetUnmarshaller(new AddressFactory());
    private static final MatchingDatasetToNonMatchingAttributesMapper MATCHING_DATASET_MAPPER = new MatchingDatasetToNonMatchingAttributesMapper();
    private static final Logger LOG = LoggerFactory.getLogger(EidasAuthnResponseAttributesHashLogger.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final MessageDigest MESSAGE_DIGEST;

    static {
        OBJECT_MAPPER.registerModule(new JavaTimeModule());

        try {
            MESSAGE_DIGEST = MessageDigest.getInstance(JCAConstants.DIGEST_SHA256);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private EidasAuthnResponseAttributesHashLogger() {
    }

    public static void logEidasAttributesHash(NonMatchingAttributes attributes, String pid, String requestId, URI destination) {
        logExtractedAttributes(attributes, requestId, destination.toString(), pid);
    }

    public static void logEidasAttributesHash(Assertion assertion, Response response, String hashingEntityId) {
        final NonMatchingAttributes attributes = MATCHING_DATASET_MAPPER.mapToNonMatchingAttributes(MATCHING_DATASET_UNMARSHALLER.fromAssertion(assertion));
        logExtractedAttributes(attributes, response.getInResponseTo(), response.getDestination(), getHashedPid(assertion, hashingEntityId));
    }

    private static void logExtractedAttributes(NonMatchingAttributes attributes, String requestId, String destination, String pid) {
        final HashableResponseAttributes attributesToHash = new HashableResponseAttributes();

        if (attributes != null) {
            attributes.getFirstNames().stream()
                    .filter(NonMatchingVerifiableAttribute::isVerified)
                    .min(attributeComparator())
                    .ifPresent(firstName -> attributesToHash.setFirstName(firstName.getValue()));

            attributes.getMiddleNames().stream()
                    .sorted(attributeComparator())
                    .forEach(middleName -> attributesToHash.addMiddleName(middleName.getValue()));

            attributes.getSurnames().stream()
                    .sorted(attributeComparator())
                    .forEach(surname -> attributesToHash.addSurname(surname.getValue()));

            attributes.getDatesOfBirth().stream()
                    .filter(NonMatchingVerifiableAttribute::isVerified)
                    .min(attributeComparator())
                    .ifPresent(dateOfBirth -> attributesToHash.setDateOfBirth(dateOfBirth.getValue()));
        }

        attributesToHash.setPid(pid);
        logHash(requestId, destination, attributesToHash);
    }

    private static String getHashedPid(Assertion assertion, String hashingEntityId) {
        return UserIdHashFactory.hashId(
                hashingEntityId,
                assertion.getIssuer().getValue(),
                assertion.getSubject().getNameID().getValue(),
                Optional.of(AuthnContext.LEVEL_2));
    }

    private static void logHash(String requestId, String destination, HashableResponseAttributes responseAttributes) {
        try {
            MDC.put(MDC_KEY_EIDAS_REQUEST_ID, requestId);
            MDC.put(MDC_KEY_EIDAS_DESTINATION, destination);
            MDC.put(MDC_KEY_EIDAS_USER_HASH, buildHash(responseAttributes));
            LOG.info("Hash of eIDAS user attributes");
        } finally {
            MDC.remove(MDC_KEY_EIDAS_REQUEST_ID);
            MDC.remove(MDC_KEY_EIDAS_DESTINATION);
            MDC.remove(MDC_KEY_EIDAS_USER_HASH);
        }
    }

    private static String buildHash(HashableResponseAttributes responseAttributes) {
        String attributesString;
        try {
            attributesString = OBJECT_MAPPER.writeValueAsString(responseAttributes);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }

        return Hex.encodeHexString(MESSAGE_DIGEST.digest(attributesString.getBytes(StandardCharsets.UTF_8)));
    }
}
