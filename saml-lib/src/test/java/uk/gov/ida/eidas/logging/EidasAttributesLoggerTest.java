package uk.gov.ida.eidas.logging;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.extensions.Date;
import uk.gov.ida.saml.core.extensions.PersonName;
import uk.gov.ida.saml.hub.factories.UserIdHashFactory;
import uk.gov.ida.verifyserviceprovider.dto.NonMatchingAttributes;
import uk.gov.ida.verifyserviceprovider.dto.NonMatchingTransliterableAttribute;
import uk.gov.ida.verifyserviceprovider.dto.NonMatchingVerifiableAttribute;

import java.net.URI;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class EidasAttributesLoggerTest {

    @Mock
    private EidasResponseAttributesHashLogger hashLogger;

    @Mock
    private HubResponseTranslatorRequestInterface hubResponseTranslatorRequest;

    @Mock
    private TranslatedHubResponseInterface translatedHubResponse;

    @Mock
    private NonMatchingAttributes attributes;

    @Mock
    private Response response;

    @Mock
    private Attribute attribute;

    @Mock
    private AttributeStatement attributeStatement;

    @Mock
    private NameID nameID;

    @Mock
    private Subject subject;

    @Mock
    private Issuer issuer;

    @Mock
    private Assertion assertion;


    private String entityId = "entityId";
    private String hashedPid = "f5f02791bb8eb83e81759b6f1ee744795048c2b45484842e403a42034fddd2c9";
    private String unHashedPid = "unHashedPid";
    private String requestId = "requestId";
    private String issuerId = "issuer";
    private URI destination = URI.create("http://destination");
    private EidasAttributesLogger preExtractedEidasAttributesLogger;
    private EidasAttributesLogger assertionContainedEidasAttributesLogger;

    @Before
    public void setUp() {
        when(translatedHubResponse.getAttributes()).thenReturn(attributes);
        when(translatedHubResponse.getPid()).thenReturn(hashedPid);

        when(hubResponseTranslatorRequest.getRequestId()).thenReturn(requestId);
        when(hubResponseTranslatorRequest.getDestinationUrl()).thenReturn(destination);

        when(response.getInResponseTo()).thenReturn(requestId);
        when(response.getDestination()).thenReturn(destination.toString());

        when(attributeStatement.getAttributes()).thenReturn(Arrays.asList(attribute));

        when(nameID.getValue()).thenReturn(unHashedPid);

        when(subject.getNameID()).thenReturn(nameID);

        when(issuer.getValue()).thenReturn(issuerId);

        when(assertion.getAttributeStatements()).thenReturn(Arrays.asList(attributeStatement));
        when(assertion.getSubject()).thenReturn(subject);
        when(assertion.getIssuer()).thenReturn(issuer);

        preExtractedEidasAttributesLogger = new EidasAttributesLogger(
                () -> hashLogger,
                null
        );
        assertionContainedEidasAttributesLogger = new EidasAttributesLogger(
                () -> hashLogger,
                new UserIdHashFactory(entityId)
        );
    }
    
    @Test
    public void fromProxyNodeOnlyFirstVerifiedFirstNameIsHashed() {
        List<NonMatchingTransliterableAttribute> firstNames = new ArrayList<>();

        firstNames.add(new NonMatchingTransliterableAttribute("John", "John", false, LocalDate.now(), LocalDate.now()));
        firstNames.add(new NonMatchingTransliterableAttribute("Paul", "Paul", true, LocalDate.now(), LocalDate.now()));
        firstNames.add(new NonMatchingTransliterableAttribute("George", "George", false, LocalDate.now(), LocalDate.now()));

        when(attributes.getFirstNames()).thenReturn(firstNames);

        preExtractedEidasAttributesLogger.logEidasAttributesAsHash(hubResponseTranslatorRequest, translatedHubResponse);

        verify(hashLogger).setPid(hashedPid);
        verify(hashLogger).setFirstName("Paul");
        verify(hashLogger).logHashFor(requestId, destination.toString());
        verifyNoMoreInteractions(hashLogger);
    }

    @Test
    public void fromHubOnlyFirstVerifiedFirstNameIsHashed() {
        PersonName attributeValue0 = mock(PersonName.class);
        when(attributeValue0.getVerified()).thenReturn(false);
        when(attributeValue0.getValue()).thenReturn("John");

        PersonName attributeValue1 = mock(PersonName.class);
        when(attributeValue1.getVerified()).thenReturn(true);
        when(attributeValue1.getValue()).thenReturn("Paul");

        PersonName attributeValue2 = mock(PersonName.class);
        when(attributeValue2.getVerified()).thenReturn(true);
        when(attributeValue2.getValue()).thenReturn("George");

        setUpAttributeMock(
                Arrays.asList(attributeValue0, attributeValue1, attributeValue2),
                IdaConstants.Attributes_1_1.Firstname.NAME
        );

        assertionContainedEidasAttributesLogger.logEidasAttributesAsHash(assertion, response);

        verify(hashLogger).setPid(hashedPid);
        verify(hashLogger).setFirstName("Paul");
        verify(hashLogger).logHashFor(requestId, destination.toString());
        verifyNoMoreInteractions(hashLogger);
    }

    @Test
    public void fromProxyNodeUnverifiedFirstNamesNeverLogged() {
        List<NonMatchingTransliterableAttribute> firstNames = new ArrayList<>();

        firstNames.add(new NonMatchingTransliterableAttribute("John", "John", false, LocalDate.now(), LocalDate.now()));
        firstNames.add(new NonMatchingTransliterableAttribute("Paul", "Paul", false, LocalDate.now(), LocalDate.now()));
        firstNames.add(new NonMatchingTransliterableAttribute("George", "George", false, LocalDate.now(), LocalDate.now()));

        when(attributes.getFirstNames()).thenReturn(firstNames);

        preExtractedEidasAttributesLogger.logEidasAttributesAsHash(hubResponseTranslatorRequest, translatedHubResponse);

        verify(hashLogger).setPid(hashedPid);
        verify(hashLogger, never()).setFirstName(any());
        verify(hashLogger).logHashFor(requestId, destination.toString());
        verifyNoMoreInteractions(hashLogger);
    }

    @Test
    public void fromHubNodeUnverifiedFirstNamesNeverLogged() {
        PersonName attributeValue0 = mock(PersonName.class);
        when(attributeValue0.getVerified()).thenReturn(false);
        when(attributeValue0.getValue()).thenReturn("John");

        PersonName attributeValue1 = mock(PersonName.class);
        when(attributeValue1.getVerified()).thenReturn(false);
        when(attributeValue1.getValue()).thenReturn("Paul");

        PersonName attributeValue2 = mock(PersonName.class);
        when(attributeValue2.getVerified()).thenReturn(false);
        when(attributeValue2.getValue()).thenReturn("George");

        setUpAttributeMock(
                Arrays.asList(attributeValue0, attributeValue1, attributeValue2),
                IdaConstants.Attributes_1_1.Firstname.NAME
        );

        assertionContainedEidasAttributesLogger.logEidasAttributesAsHash(assertion, response);

        verify(hashLogger).setPid(hashedPid);
        verify(hashLogger, never()).setFirstName(any());
        verify(hashLogger).logHashFor(requestId, destination.toString());
        verifyNoMoreInteractions(hashLogger);
    }

    @Test
    public void fromProxyNodeOnlyFirstVerifiedDateOfBirthIsHashed() {
        List<NonMatchingVerifiableAttribute<LocalDate>> datesOfBirth = new ArrayList<>();

        datesOfBirth.add(new NonMatchingVerifiableAttribute<>(LocalDate.of(1940, 10, 9), false, LocalDate.now(), LocalDate.now()));
        datesOfBirth.add(new NonMatchingVerifiableAttribute<>(LocalDate.of(1942, 6, 18), false, LocalDate.now(), LocalDate.now()));
        datesOfBirth.add(new NonMatchingVerifiableAttribute<>(LocalDate.of(1943, 2, 25),true, LocalDate.now(), LocalDate.now()));

        when(attributes.getDatesOfBirth()).thenReturn(datesOfBirth);

        preExtractedEidasAttributesLogger.logEidasAttributesAsHash(hubResponseTranslatorRequest, translatedHubResponse);

        verify(hashLogger).setPid(hashedPid);
        verify(hashLogger).setDateOfBirth(LocalDate.of(1943, 2, 25));
        verify(hashLogger).logHashFor(requestId, destination.toString());
        verifyNoMoreInteractions(hashLogger);
    }

    @Test
    public void fromHubNodeOnlyFirstVerifiedDateOfBirthIsHashed() {
        Date attributeValue0 = mock(Date.class);
        when(attributeValue0.getVerified()).thenReturn(false);
        when(attributeValue0.getValue()).thenReturn("1940-10-09");

        Date attributeValue1 = mock(Date.class);
        when(attributeValue1.getVerified()).thenReturn(false);
        when(attributeValue1.getValue()).thenReturn("1942-06-18");

        Date attributeValue2 = mock(Date.class);
        when(attributeValue2.getVerified()).thenReturn(true);
        when(attributeValue2.getValue()).thenReturn("1943-02-25");

        setUpAttributeMock(
                Arrays.asList(attributeValue0, attributeValue1, attributeValue2),
                IdaConstants.Attributes_1_1.DateOfBirth.NAME
        );

        assertionContainedEidasAttributesLogger.logEidasAttributesAsHash(assertion, response);

        verify(hashLogger).setPid(hashedPid);
        verify(hashLogger).setDateOfBirth(LocalDate.of(1943, 2, 25));
        verify(hashLogger).logHashFor(requestId, destination.toString());
        verifyNoMoreInteractions(hashLogger);
    }

    @Test
    public void fromProxyNodeAllMiddleNamesHashedInCorrectOrder() {
        List<NonMatchingVerifiableAttribute<String>> middleNames = new ArrayList<>();

        middleNames.add(new NonMatchingVerifiableAttribute<>("Winston", false, LocalDate.now(), LocalDate.now()));
        middleNames.add(new NonMatchingVerifiableAttribute<>("James", false, LocalDate.now(), LocalDate.now()));
        middleNames.add(new NonMatchingVerifiableAttribute<>("Carl",true, LocalDate.now(), LocalDate.now()));

        when(attributes.getMiddleNames()).thenReturn(middleNames);

        preExtractedEidasAttributesLogger.logEidasAttributesAsHash(hubResponseTranslatorRequest, translatedHubResponse);

        InOrder inOrder = inOrder(hashLogger);
        verify(hashLogger).setPid(hashedPid);
        inOrder.verify(hashLogger).addMiddleName("Winston");
        inOrder.verify(hashLogger).addMiddleName("James");
        inOrder.verify(hashLogger).addMiddleName("Carl");
        verify(hashLogger).logHashFor(requestId, destination.toString());
        verifyNoMoreInteractions(hashLogger);
    }

    @Test
    public void fromHubAllMiddleNamesHashedInCorrectOrder() {
        PersonName attributeValue0 = mock(PersonName.class);
        when(attributeValue0.getVerified()).thenReturn(false);
        when(attributeValue0.getValue()).thenReturn("Winston");
        when(attributeValue0.getTo()).thenReturn(DateTime.now().minusDays(2));

        PersonName attributeValue1 = mock(PersonName.class);
        when(attributeValue1.getVerified()).thenReturn(false);
        when(attributeValue1.getValue()).thenReturn("James");
        when(attributeValue1.getTo()).thenReturn(DateTime.now().minusDays(1));

        PersonName attributeValue2 = mock(PersonName.class);
        when(attributeValue2.getVerified()).thenReturn(true);
        when(attributeValue2.getValue()).thenReturn("Carl");
        when(attributeValue2.getTo()).thenReturn(DateTime.now());

        setUpAttributeMock(
                Arrays.asList(attributeValue0, attributeValue1, attributeValue2),
                IdaConstants.Attributes_1_1.Middlename.NAME
        );

        assertionContainedEidasAttributesLogger.logEidasAttributesAsHash(assertion, response);

        InOrder inOrder = inOrder(hashLogger);
        verify(hashLogger).setPid(hashedPid);
        inOrder.verify(hashLogger).addMiddleName("Carl");
        inOrder.verify(hashLogger).addMiddleName("James");
        inOrder.verify(hashLogger).addMiddleName("Winston");
        verify(hashLogger).logHashFor(requestId, destination.toString());
        verifyNoMoreInteractions(hashLogger);
    }

    @Test
    public void fromProxyNodeAllSurnamesHashedInCorrectOrder() {
        List<NonMatchingTransliterableAttribute> surnames = new ArrayList<>();

        surnames.add(new NonMatchingTransliterableAttribute("Lennon", "Lennon", true, LocalDate.now(), LocalDate.now()));
        surnames.add(new NonMatchingTransliterableAttribute("McCartney", "McCartney",false, LocalDate.now(), LocalDate.now()));
        surnames.add(new NonMatchingTransliterableAttribute("Harrison", "Harrison", true, LocalDate.now(), LocalDate.now()));

        when(attributes.getSurnames()).thenReturn(surnames);

        preExtractedEidasAttributesLogger.logEidasAttributesAsHash(hubResponseTranslatorRequest, translatedHubResponse);

        InOrder inOrder = inOrder(hashLogger);
        verify(hashLogger).setPid(hashedPid);
        inOrder.verify(hashLogger).addSurname("Lennon");
        inOrder.verify(hashLogger).addSurname("McCartney");
        inOrder.verify(hashLogger).addSurname("Harrison");
        verify(hashLogger).logHashFor(requestId, destination.toString());
        verifyNoMoreInteractions(hashLogger);
    }

    @Test
    public void fromHubAllSurnamesHashedInCorrectOrder() {
        PersonName attributeValue0 = mock(PersonName.class);
        when(attributeValue0.getVerified()).thenReturn(false);
        when(attributeValue0.getValue()).thenReturn("Lennon");
        when(attributeValue0.getTo()).thenReturn(DateTime.now().minusDays(2));

        PersonName attributeValue1 = mock(PersonName.class);
        when(attributeValue1.getVerified()).thenReturn(false);
        when(attributeValue1.getValue()).thenReturn("McCartney");
        when(attributeValue1.getTo()).thenReturn(DateTime.now());

        PersonName attributeValue2 = mock(PersonName.class);
        when(attributeValue2.getVerified()).thenReturn(true);
        when(attributeValue2.getValue()).thenReturn("Harrison");
        when(attributeValue2.getTo()).thenReturn(DateTime.now().minusDays(1));

        setUpAttributeMock(
                Arrays.asList(attributeValue0, attributeValue1, attributeValue2),
                IdaConstants.Attributes_1_1.Surname.NAME
        );

        assertionContainedEidasAttributesLogger.logEidasAttributesAsHash(assertion, response);

        InOrder inOrder = inOrder(hashLogger);
        verify(hashLogger).setPid(hashedPid);
        inOrder.verify(hashLogger).addSurname("McCartney");
        inOrder.verify(hashLogger).addSurname("Harrison");
        inOrder.verify(hashLogger).addSurname("Lennon");
        verify(hashLogger).logHashFor(requestId, destination.toString());
        verifyNoMoreInteractions(hashLogger);
    }

    private void setUpAttributeMock(List attributes, String attributeNameConstant) {
        when(attribute.getName()).thenReturn(attributeNameConstant);
        when(attribute.getAttributeValues()).thenReturn(attributes);
    }
}
