package uk.gov.ida.eidas.logging;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import uk.gov.ida.saml.core.domain.AddressFactory;
import uk.gov.ida.saml.core.domain.AuthnContext;
import uk.gov.ida.saml.core.domain.MatchingDataset;
import uk.gov.ida.saml.core.transformers.VerifyMatchingDatasetUnmarshaller;
import uk.gov.ida.saml.hub.factories.UserIdHashFactory;
import uk.gov.ida.verifyserviceprovider.mappers.MatchingDatasetToNonMatchingAttributesMapper;
import uk.gov.ida.verifyserviceprovider.dto.NonMatchingAttributes;
import uk.gov.ida.verifyserviceprovider.dto.NonMatchingVerifiableAttribute;

import java.net.URI;
import java.util.Optional;
import java.util.function.Supplier;

public class EidasAttributesLogger {
    private final Supplier<EidasResponseAttributesHashLogger> loggerSupplier;
    private final UserIdHashFactory userIdHashFactory;

    public EidasAttributesLogger(
            Supplier<EidasResponseAttributesHashLogger> loggerSupplier,
            UserIdHashFactory userIdHashFactory) {
        this.loggerSupplier = loggerSupplier;
        this.userIdHashFactory = userIdHashFactory;
    }

    public void logEidasAttributesAsHash(
            NonMatchingAttributes attributes,
            String pid,
            String requestId,
            URI destination) {
        EidasResponseAttributesHashLogger hashLogger = loggerSupplier.get();

        hashLogger.setPid(pid);

        updateLoggerAndLog(
                hashLogger,
                attributes,
                requestId,
                destination.toString()
        );
    }

    public void logEidasAttributesAsHash(Assertion assertion, Response response) {
        EidasResponseAttributesHashLogger hashLogger = loggerSupplier.get();
        NonMatchingAttributes attributes = extractAttributes(assertion);

        hashLogger.setPid(
                getHashedPid(assertion, userIdHashFactory)
        );

        updateLoggerAndLog(
                hashLogger,
                attributes,
                response.getInResponseTo(),
                response.getDestination()
        );
    }

    private void updateLoggerAndLog(
            EidasResponseAttributesHashLogger hashLogger,
            NonMatchingAttributes attributes,
            String requestId,
            String destination) {
        if (attributes != null) {
            attributes.getFirstNames().stream()
                    .filter(NonMatchingVerifiableAttribute::isVerified)
                    .findFirst()
                    .ifPresent(firstName -> hashLogger.setFirstName(firstName.getValue()));

            attributes.getMiddleNames().forEach(
                    middleName -> hashLogger.addMiddleName(middleName.getValue())
            );

            attributes.getSurnames().forEach(
                    surname -> hashLogger.addSurname(surname.getValue())
            );

            attributes.getDatesOfBirth().stream()
                    .filter(NonMatchingVerifiableAttribute::isVerified)
                    .findFirst()
                    .ifPresent(dateOfBirth -> hashLogger.setDateOfBirth(dateOfBirth.getValue()));
        }

        hashLogger.logHashFor(
                requestId,
                destination
        );
    }

    private NonMatchingAttributes extractAttributes(Assertion assertion) {
        VerifyMatchingDatasetUnmarshaller verifyMatchingDatasetUnmarshaller = new VerifyMatchingDatasetUnmarshaller(new AddressFactory());
        MatchingDataset matchingDataset = verifyMatchingDatasetUnmarshaller.fromAssertion(assertion);
        MatchingDatasetToNonMatchingAttributesMapper mapper = new MatchingDatasetToNonMatchingAttributesMapper();

        return mapper.mapToNonMatchingAttributes(matchingDataset);
    }

    private String getHashedPid(Assertion assertion, UserIdHashFactory userIdHashFactory) {
        return userIdHashFactory.hashId(
                assertion.getIssuer().getValue(),
                assertion.getSubject().getNameID().getValue(),
                Optional.of(AuthnContext.LEVEL_2));
    }
}
