package uk.gov.ida.saml.core.transformers;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import org.apache.commons.lang.reflect.FieldUtils;
import org.joda.time.DateTime;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.MockitoJUnitRunner;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class EidasResponseAttributesHashLoggerTest {

    @Test
    public void testAHashCanBeCreatedWithNoInput() {
        EidasResponseAttributesHashLogger logger = EidasResponseAttributesHashLogger.instance();
        String hash = buildHash(logger);
        assertThat(hash).isNotBlank();
    }

    @Test
    public void testDifferentInputProduceDifferentHashes() {
        DateTime now = DateTime.now();

        EidasResponseAttributesHashLogger logger1 = EidasResponseAttributesHashLogger.instance();
        logger1.setPid("a");
        logger1.setFirstName("fn");
        logger1.addMiddleName("mn");
        logger1.addSurname("sn");
        logger1.setDateOfBirth(now);
        String hash1 = buildHash(logger1);

        EidasResponseAttributesHashLogger logger2 = EidasResponseAttributesHashLogger.instance();
        logger2.setPid("different pid");
        logger2.setFirstName("fn");
        logger2.addMiddleName("mn");
        logger2.addSurname("sn");
        logger2.setDateOfBirth(now);
        String hash2 = buildHash(logger2);

        assertThat(hash1).isNotEqualTo(hash2);
    }

    @Test
    public void testSamePidsProduceSameHashes() {
        DateTime now = DateTime.now();

        EidasResponseAttributesHashLogger logger1 = EidasResponseAttributesHashLogger.instance();
        logger1.setPid("a");
        logger1.setFirstName("fn");
        logger1.addMiddleName("mn");
        logger1.addSurname("sn");
        logger1.setDateOfBirth(now);
        String hash1 = buildHash(logger1);

        EidasResponseAttributesHashLogger logger2 = EidasResponseAttributesHashLogger.instance();
        logger2.setPid("a");
        logger2.setFirstName("fn");
        logger2.addMiddleName("mn");
        logger2.addSurname("sn");
        logger2.setDateOfBirth(now);
        String hash2 = buildHash(logger2);
        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    public void testOrderingOfMiddleNamesAffectsHash() {
        EidasResponseAttributesHashLogger logger1 = EidasResponseAttributesHashLogger.instance();
        logger1.addMiddleName("mn1");
        logger1.addMiddleName("mn2");
        String hash1 = buildHash(logger1);

        EidasResponseAttributesHashLogger logger2 = EidasResponseAttributesHashLogger.instance();
        logger2.addMiddleName("mn1");
        logger2.addMiddleName("mn2");
        assertThat(hash1).isEqualTo(buildHash(logger2));

        EidasResponseAttributesHashLogger logger3 = EidasResponseAttributesHashLogger.instance();
        logger3.addMiddleName("mn2");
        logger3.addMiddleName("mn1");
        assertThat(hash1).isNotEqualTo(buildHash(logger3));


    }

    @Test
    public void testDateOfBirthIsStoredAndHashedAsLocalDate() {
        DateTime beginningOfToday = new DateTime().withTimeAtStartOfDay();
        DateTime oneHourLater = beginningOfToday.plusHours(1);
        DateTime tomorrow = beginningOfToday.plusDays(1).withTimeAtStartOfDay();

        EidasResponseAttributesHashLogger logger = EidasResponseAttributesHashLogger.instance();
        logger.setDateOfBirth(beginningOfToday);
        String hash1 = buildHash(logger);

        logger.setDateOfBirth(oneHourLater);
        String hash2 = buildHash(logger);
        assertThat(hash1).isEqualTo(hash2);

        logger.setDateOfBirth(tomorrow);
        String hash3 = buildHash(logger);
        assertThat(hash2).isNotEqualTo(hash3);
    }

    @Test
    public void testUpdatingFieldsChangesHash() {
        EidasResponseAttributesHashLogger logger1 = EidasResponseAttributesHashLogger.instance();
        logger1.setPid("a");
        String hash1 = buildHash(logger1);
        logger1.setPid("b");
        assertThat(hash1).isNotEqualTo(buildHash(logger1));
    }

    @Test
    public void testLoggingOfHashAndLevel() throws IllegalAccessException {
        Appender<ILoggingEvent> appender = mock(Appender.class);
        Logger logger = (Logger) LoggerFactory.getLogger(EidasResponseAttributesHashLogger.class);
        logger.addAppender(appender);
        ArgumentCaptor<ILoggingEvent> loggingEventArgumentCaptor = ArgumentCaptor.forClass(ILoggingEvent.class);

        EidasResponseAttributesHashLogger hashLogger = EidasResponseAttributesHashLogger.instance();
        FieldUtils.writeField(hashLogger, "log", logger, true);
        hashLogger.setPid("a");
        String hash = buildHash(hashLogger);
        hashLogger.logHashFor("a request id", "a destination");
        verify(appender).doAppend(loggingEventArgumentCaptor.capture());
        ILoggingEvent loggingEvent = loggingEventArgumentCaptor.getValue();
        assertThat(loggingEvent.getLevel()).isEqualTo(Level.INFO);
        assertThat(loggingEvent.getMessage()).doesNotContain("a request id", "a destination", hash);
        Map<String, String> mdcPropertyMap = loggingEvent.getMDCPropertyMap();
        assertThat(mdcPropertyMap.get("eidasRequestId")).isEqualTo("a request id");
        assertThat(mdcPropertyMap.get("eidasDestination")).isEqualTo("a destination");
        assertThat(mdcPropertyMap.get("eidasUserHash")).isEqualTo(hash);
    }

    @Test
    public void testExpectedJsonProvidesSameHashCode() {
        EidasResponseAttributesHashLogger logger = EidasResponseAttributesHashLogger.instance();
        String expectedStringToHash = "{\"pid\":\"a\",\"firstName\":\"fn\",\"middleNames\":[\"m1\",\"mn2\"],\"surnames\":[\"sn\"],\"dateOfBirth\":\"2019-03-24\"}";
        String expectedHash = getExpectedHash(logger, expectedStringToHash);

        DateTime startOfToday = DateTime.now()
                .withYear(2019)
                .withMonthOfYear(3)
                .withDayOfMonth(24)
                .withTimeAtStartOfDay();
        logger.setPid("a");
        logger.setFirstName("fn");
        logger.addMiddleName("m1");
        logger.addMiddleName("mn2");
        logger.addSurname("sn");
        logger.setDateOfBirth(startOfToday);
        assertThat(buildHash(logger)).isEqualTo(expectedHash);
    }

    @Test
    public void testExpectedMininalJsonProvidesSameHashCode() {
        EidasResponseAttributesHashLogger logger = EidasResponseAttributesHashLogger.instance();
        String expectedStringToHash = "{\"pid\":\"a\",\"firstName\":\"fn\",\"surnames\":[\"sn\"]}";
        String expectedHash = getExpectedHash(logger, expectedStringToHash);
        logger.setPid("a");
        logger.setFirstName("fn");
        logger.addSurname("sn");
        assertThat(buildHash(logger)).isEqualTo(expectedHash);
    }

    private String getExpectedHash(EidasResponseAttributesHashLogger logger, String expectedStringToHash) {
        try {
            Method method = logger.getClass().getDeclaredMethod("hashFor", String.class);
            method.setAccessible(true);
            return (String) method.invoke(logger, expectedStringToHash);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String buildHash(EidasResponseAttributesHashLogger logger) {
        try {
            Method method = logger.getClass().getDeclaredMethod("buildHash");
            method.setAccessible(true);
            return (String) method.invoke(logger);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}