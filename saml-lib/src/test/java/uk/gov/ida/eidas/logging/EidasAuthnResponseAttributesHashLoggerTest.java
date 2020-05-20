package uk.gov.ida.eidas.logging;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.slf4j.LoggerFactory;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.domain.NonMatchingAttributes;
import uk.gov.ida.saml.core.domain.NonMatchingTransliterableAttribute;
import uk.gov.ida.saml.core.domain.NonMatchingVerifiableAttribute;
import uk.gov.ida.saml.core.extensions.Date;
import uk.gov.ida.saml.core.extensions.PersonName;
import uk.gov.ida.saml.core.extensions.StringBasedMdsAttributeValue;

import java.lang.reflect.Method;
import java.net.URI;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.ida.eidas.logging.EidasAuthnResponseAttributesHashLogger.MDC_KEY_EIDAS_USER_HASH;

@RunWith(MockitoJUnitRunner.class)
public class EidasAuthnResponseAttributesHashLoggerTest {

    @Mock
    private Appender<ILoggingEvent> appender;

    @Captor
    private ArgumentCaptor<ILoggingEvent> loggingEventArgumentCaptor;

    @Mock
    private NonMatchingAttributes preExtractedAttributes;

    @Mock
    private Response response;

    @Mock
    private AttributeStatement attributeStatement;

    @Mock
    private NameID nameID;

    @Mock
    private Subject subject;

    @Mock
    private Assertion assertion;

    private List<Attribute> attributes;

    private final LocalDate now = LocalDate.now();
    private final String entityId = "entityId";
    private final String unHashedPid = "unHashedPid";
    private final String requestId = "requestId";
    private final String issuerId = "issuer";
    private final URI destination = URI.create("http://destination");

    @Before
    public void setUp() {
        final Logger Logger = (Logger) LoggerFactory.getLogger(EidasAuthnResponseAttributesHashLogger.class);
        Logger.addAppender(appender);

        when(response.getInResponseTo()).thenReturn(requestId);
        when(response.getDestination()).thenReturn(destination.toString());

        attributes = new ArrayList<>();
        when(attributeStatement.getAttributes()).thenReturn(attributes);

        when(nameID.getValue()).thenReturn(unHashedPid);

        when(subject.getNameID()).thenReturn(nameID);

        when(assertion.getAttributeStatements()).thenReturn(singletonList(attributeStatement));
        when(assertion.getSubject()).thenReturn(subject);
    }

    @Test
    public void shouldHashOnlyFirstVerifiedFirstName() {
        final List<NonMatchingTransliterableAttribute> firstNames = Arrays.asList(
                new NonMatchingTransliterableAttribute("John", "John", false, now, now),
                new NonMatchingTransliterableAttribute("Paul", "Paul", true, null, now.minusDays(2)),
                new NonMatchingTransliterableAttribute("George", "George", true, now, now));

        final HashableResponseAttributes validAttributesToHash = new HashableResponseAttributes();
        validAttributesToHash.setRequestId(requestId);
        validAttributesToHash.setFirstName("George");

        checkThatSameHashesAreLoggedForBothMethods(firstNames, null, null, null, validAttributesToHash);
    }

    @Test
    public void shouldHashOnlyFirstVerifiedFirstNameInCorrectOrder() {
        final List<NonMatchingTransliterableAttribute> firstNames = Arrays.asList(
                new NonMatchingTransliterableAttribute("John", "John", false, now, now),
                new NonMatchingTransliterableAttribute("Paul", "Paul", true, null, null),
                new NonMatchingTransliterableAttribute("George", "George", true, null, null));

        final HashableResponseAttributes validAttributesToHash = new HashableResponseAttributes();
        validAttributesToHash.setRequestId(requestId);
        validAttributesToHash.setFirstName("Paul");

        checkThatSameHashesAreLoggedForBothMethods(firstNames, null, null, null, validAttributesToHash);
    }

    @Test
    public void shouldNotHashUnverifiedFirstNames() {
        final List<NonMatchingTransliterableAttribute> firstNames = Arrays.asList(
                new NonMatchingTransliterableAttribute("John", "John", false, now, now),
                new NonMatchingTransliterableAttribute("Paul", "Paul", false, now, now),
                new NonMatchingTransliterableAttribute("George", "George", false, now, now));

        final HashableResponseAttributes validAttributesToHash = new HashableResponseAttributes();
        validAttributesToHash.setRequestId(requestId);

        checkThatSameHashesAreLoggedForBothMethods(firstNames, null, null, null, validAttributesToHash);
    }

    @Test
    public void shouldHashOnlyFirstVerifiedDateOfBirth() {
        final List<NonMatchingVerifiableAttribute<LocalDate>> datesOfBirth = Arrays.asList(
                new NonMatchingVerifiableAttribute<>(LocalDate.of(1940, 10, 9), false, now, now),
                new NonMatchingVerifiableAttribute<>(LocalDate.of(1942, 6, 18), false, now, now),
                new NonMatchingVerifiableAttribute<>(LocalDate.of(1943, 2, 25), true, now, now));

        final HashableResponseAttributes validAttributesToHash = new HashableResponseAttributes();
        validAttributesToHash.setRequestId(requestId);
        validAttributesToHash.setDateOfBirth(LocalDate.of(1943, 2, 25));

        checkThatSameHashesAreLoggedForBothMethods(null, datesOfBirth, null, null, validAttributesToHash);
    }

    @Test
    public void shouldHashAllMiddleNames() {
        final List<NonMatchingVerifiableAttribute<String>> middleNames = Arrays.asList(
                new NonMatchingVerifiableAttribute<>("Winston", false, now, now),
                new NonMatchingVerifiableAttribute<>("James", false, now, now),
                new NonMatchingVerifiableAttribute<>("Carl", false, now, now));

        final HashableResponseAttributes validAttributesToHash = new HashableResponseAttributes();
        validAttributesToHash.setRequestId(requestId);
        validAttributesToHash.addMiddleName("Winston");
        validAttributesToHash.addMiddleName("James");
        validAttributesToHash.addMiddleName("Carl");

        checkThatSameHashesAreLoggedForBothMethods(null, null, middleNames, null, validAttributesToHash);
    }

    @Test
    public void shouldHashAllMiddleNamesInCorrectOrder() {
        final List<NonMatchingVerifiableAttribute<String>> middleNames = Arrays.asList(
                new NonMatchingVerifiableAttribute<>("Winston", false, null, now.minusDays(2)),
                new NonMatchingVerifiableAttribute<>("James", false, null, now.minusDays(1)),
                new NonMatchingVerifiableAttribute<>("Carl", true, null, now));

        final HashableResponseAttributes validAttributesToHash = new HashableResponseAttributes();
        validAttributesToHash.setRequestId(requestId);
        validAttributesToHash.addMiddleName("Carl");
        validAttributesToHash.addMiddleName("James");
        validAttributesToHash.addMiddleName("Winston");

        checkThatSameHashesAreLoggedForBothMethods(null, null, middleNames, null, validAttributesToHash);
    }

    @Test
    public void shouldHashAllSurnames() {
        final List<NonMatchingTransliterableAttribute> surnames = Arrays.asList(
                new NonMatchingTransliterableAttribute("McCartney", "McCartney", true, now, now),
                new NonMatchingTransliterableAttribute("Lennon", "Lennon", true, now, now),
                new NonMatchingTransliterableAttribute("Harrison", "Harrison", true, now, now));

        final HashableResponseAttributes validAttributesToHash = new HashableResponseAttributes();
        validAttributesToHash.setRequestId(requestId);
        validAttributesToHash.addSurname("McCartney");
        validAttributesToHash.addSurname("Lennon");
        validAttributesToHash.addSurname("Harrison");

        checkThatSameHashesAreLoggedForBothMethods(null, null, null, surnames, validAttributesToHash);
    }

    @Test
    public void shouldHashAllSurnamesInCorrectOrder() {
        final List<NonMatchingTransliterableAttribute> surnames = Arrays.asList(
                new NonMatchingTransliterableAttribute("McCartney", "McCartney", false, now, now),
                new NonMatchingTransliterableAttribute("Lennon", "Lennon", true, null, now),
                new NonMatchingTransliterableAttribute("Harrison", "Harrison", true, now, null));

        final HashableResponseAttributes validAttributesToHash = new HashableResponseAttributes();
        validAttributesToHash.setRequestId(requestId);
        validAttributesToHash.addSurname("Harrison");
        validAttributesToHash.addSurname("Lennon");
        validAttributesToHash.addSurname("McCartney");

        checkThatSameHashesAreLoggedForBothMethods(null, null, null, surnames, validAttributesToHash);
    }

    @Test
    public void shouldLogTheSameHashWithMultipleAttributes() {
        final List<NonMatchingTransliterableAttribute> firstNames = Arrays.asList(
                new NonMatchingTransliterableAttribute("John", "John", false, now, now),
                new NonMatchingTransliterableAttribute("Paul", "Paul", true, null, now.minusDays(2)),
                new NonMatchingTransliterableAttribute("George", "George", true, now, now));

        final List<NonMatchingVerifiableAttribute<LocalDate>> datesOfBirth = Arrays.asList(
                new NonMatchingVerifiableAttribute<>(LocalDate.of(1940, 10, 9), false, now, now),
                new NonMatchingVerifiableAttribute<>(LocalDate.of(1942, 6, 18), false, now, now),
                new NonMatchingVerifiableAttribute<>(LocalDate.of(1943, 2, 25), true, now, now));

        final List<NonMatchingVerifiableAttribute<String>> middleNames = Arrays.asList(
                new NonMatchingVerifiableAttribute<>("Winston", false, now.minusDays(3), now.minusDays(2)),
                new NonMatchingVerifiableAttribute<>("James", false, now, now),
                new NonMatchingVerifiableAttribute<>("Carl", true, now, now));

        final List<NonMatchingTransliterableAttribute> surnames = Arrays.asList(
                new NonMatchingTransliterableAttribute("McCartney", "McCartney", false, now, now),
                new NonMatchingTransliterableAttribute("Lennon", "Lennon", true, now, now),
                new NonMatchingTransliterableAttribute("Harrison", "Harrison", true, now, null));

        final HashableResponseAttributes validAttributesToHash = new HashableResponseAttributes();
        validAttributesToHash.setRequestId(requestId);
        validAttributesToHash.setFirstName("George");
        validAttributesToHash.setDateOfBirth(LocalDate.of(1943, 2, 25));
        validAttributesToHash.addMiddleName("Carl");
        validAttributesToHash.addMiddleName("James");
        validAttributesToHash.addMiddleName("Winston");
        validAttributesToHash.addSurname("Harrison");
        validAttributesToHash.addSurname("Lennon");
        validAttributesToHash.addSurname("McCartney");

        checkThatSameHashesAreLoggedForBothMethods(firstNames, datesOfBirth, middleNames, surnames, validAttributesToHash);
    }

    private void checkThatSameHashesAreLoggedForBothMethods(
            List<NonMatchingTransliterableAttribute> firstNames,
            List<NonMatchingVerifiableAttribute<LocalDate>> datesOfBirth,
            List<NonMatchingVerifiableAttribute<String>> middleNames,
            List<NonMatchingTransliterableAttribute> surnames,
            HashableResponseAttributes validAttributesToHash) {

        if (firstNames != null) {
            when(preExtractedAttributes.getFirstNames()).thenReturn(firstNames);
            addAssertionContainedAttributes(firstNames, PersonName.class, IdaConstants.Attributes_1_1.Firstname.NAME);
        }

        if (datesOfBirth != null) {
            when(preExtractedAttributes.getDatesOfBirth()).thenReturn(datesOfBirth);
            addAssertionContainedAttributes(datesOfBirth, Date.class, IdaConstants.Attributes_1_1.DateOfBirth.NAME);
        }

        if (middleNames != null) {
            when(preExtractedAttributes.getMiddleNames()).thenReturn(middleNames);
            addAssertionContainedAttributes(middleNames, PersonName.class, IdaConstants.Attributes_1_1.Middlename.NAME);
        }

        if (surnames != null) {
            when(preExtractedAttributes.getSurnames()).thenReturn(surnames);
            addAssertionContainedAttributes(surnames, PersonName.class, IdaConstants.Attributes_1_1.Surname.NAME);
        }

        EidasAuthnResponseAttributesHashLogger.logEidasAttributesHash(preExtractedAttributes, requestId, destination);
        verify(appender, times(1)).doAppend(loggingEventArgumentCaptor.capture());
        final String preExtractedAttributesHash = loggingEventArgumentCaptor.getValue().getMDCPropertyMap().get(MDC_KEY_EIDAS_USER_HASH);

        EidasAuthnResponseAttributesHashLogger.logEidasAttributesHash(assertion, response, entityId);
        verify(appender, times(2)).doAppend(loggingEventArgumentCaptor.capture());
        final String assertionContainedAttributesHash = loggingEventArgumentCaptor.getValue().getMDCPropertyMap().get(MDC_KEY_EIDAS_USER_HASH);

        final String expectedHash = buildHash(validAttributesToHash);

        assertThat(preExtractedAttributesHash).isEqualTo(expectedHash);
        assertThat(assertionContainedAttributesHash).isEqualTo(expectedHash);
        assertThat(preExtractedAttributesHash).isEqualTo(assertionContainedAttributesHash);
    }

    private <T extends NonMatchingVerifiableAttribute<?>> void addAssertionContainedAttributes(
            List<T> values,
            Class<? extends StringBasedMdsAttributeValue> attributeClass,
            String attributeNameConstant) {

        final List<XMLObject> attributesValues = values.stream()
                .map(v -> {
                    final StringBasedMdsAttributeValue mockAttribute = mock(attributeClass);
                    when(mockAttribute.getValue()).thenReturn(v.getValue().toString());
                    when(mockAttribute.getVerified()).thenReturn(v.isVerified());
                    Optional.ofNullable(v.getFrom()).ifPresent(d -> when(mockAttribute.getFrom()).thenReturn(DateTime.parse(d.toString())));
                    Optional.ofNullable(v.getTo()).ifPresent(d -> when(mockAttribute.getTo()).thenReturn(DateTime.parse(d.toString())));
                    return (XMLObject) mockAttribute;
                }).collect(Collectors.toList());

        final Attribute attribute = mock(Attribute.class);
        when(attribute.getName()).thenReturn(attributeNameConstant);
        when(attribute.getAttributeValues()).thenReturn(attributesValues);
        attributes.add(attribute);
    }

    private String buildHash(HashableResponseAttributes responseAttributes) {
        try {
            Method method = EidasAuthnResponseAttributesHashLogger.class.getDeclaredMethod("buildHash", HashableResponseAttributes.class);
            method.setAccessible(true);
            return (String) method.invoke(null, responseAttributes);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
