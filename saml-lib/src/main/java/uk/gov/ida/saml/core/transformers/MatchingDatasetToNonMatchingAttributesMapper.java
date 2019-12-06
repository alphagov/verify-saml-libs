package uk.gov.ida.saml.core.transformers;

import uk.gov.ida.saml.core.domain.Address;
import uk.gov.ida.saml.core.domain.Gender;
import uk.gov.ida.saml.core.domain.MatchingDataset;
import uk.gov.ida.saml.core.domain.NonMatchingAddress;
import uk.gov.ida.saml.core.domain.NonMatchingAttributes;
import uk.gov.ida.saml.core.domain.NonMatchingTransliterableAttribute;
import uk.gov.ida.saml.core.domain.NonMatchingVerifiableAttribute;
import uk.gov.ida.saml.core.domain.SimpleMdsValue;
import uk.gov.ida.saml.core.domain.TransliterableMdsValue;

import java.time.LocalDate;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class MatchingDatasetToNonMatchingAttributesMapper {

    public NonMatchingAttributes mapToNonMatchingAttributes(MatchingDataset matchingDataset) {
        final List<NonMatchingTransliterableAttribute> firstNames = convertTransliterableNameAttributes(matchingDataset.getFirstNames());
        final List<NonMatchingVerifiableAttribute<LocalDate>> datesOfBirth = convertDateOfBirths(matchingDataset.getDateOfBirths());
        final List<NonMatchingVerifiableAttribute<String>> middleNames = convertNameAttributes(matchingDataset.getMiddleNames());
        final List<NonMatchingTransliterableAttribute> surnames = convertTransliterableNameAttributes(matchingDataset.getSurnames());
        final NonMatchingVerifiableAttribute<Gender> gender = matchingDataset.getGender()
                .map(this::mapToNonMatchingVerifiableAttribute)
                .orElse(null);
        final List<NonMatchingVerifiableAttribute<NonMatchingAddress>> addresses = mapAddresses(matchingDataset.getAddresses());

        return new NonMatchingAttributes(
                firstNames,
                middleNames,
                surnames,
                datesOfBirth,
                gender,
                addresses);
    }

    public static <T> Comparator<NonMatchingVerifiableAttribute<T>> attributeComparator() {
        return Comparator.<NonMatchingVerifiableAttribute<T>, LocalDate>comparing(NonMatchingVerifiableAttribute::getTo, Comparator.nullsFirst(Comparator.reverseOrder()))
                .thenComparing(NonMatchingVerifiableAttribute::isVerified, Comparator.reverseOrder())
                .thenComparing(NonMatchingVerifiableAttribute::getFrom, Comparator.nullsLast(Comparator.reverseOrder()));
    }

    private List<NonMatchingVerifiableAttribute<String>> convertNameAttributes(List<SimpleMdsValue<String>> values) {
        return values.stream()
                .map(this::mapToNonMatchingVerifiableAttribute)
                .sorted(attributeComparator())
                .collect(Collectors.toList());
    }

    private List<NonMatchingVerifiableAttribute<LocalDate>> convertDateOfBirths(List<SimpleMdsValue<org.joda.time.LocalDate>> values) {
        return values.stream()
                .map(MatchingDatasetToNonMatchingAttributesMapper::convertWrappedJodaLocalDateToJavaLocalDate)
                .map(this::mapToNonMatchingVerifiableAttribute)
                .sorted(attributeComparator())
                .collect(Collectors.toList());
    }

    private List<NonMatchingTransliterableAttribute> convertTransliterableNameAttributes(List<TransliterableMdsValue> values) {
        return values.stream()
                .map(this::mapToTransliterableAttribute)
                .sorted(attributeComparator())
                .collect(Collectors.toList());
    }


    private NonMatchingTransliterableAttribute mapToTransliterableAttribute(TransliterableMdsValue transliterableMdsValue) {
        final LocalDate from = Optional.ofNullable(transliterableMdsValue.getFrom())
                .map(MatchingDatasetToNonMatchingAttributesMapper::convertJodaDateTimeToJavaLocalDate)
                .orElse(null);

        final LocalDate to = Optional.ofNullable(transliterableMdsValue.getTo())
                .map(MatchingDatasetToNonMatchingAttributesMapper::convertJodaDateTimeToJavaLocalDate)
                .orElse(null);

        return new NonMatchingTransliterableAttribute(
                transliterableMdsValue.getValue(),
                transliterableMdsValue.getNonLatinScriptValue(),
                transliterableMdsValue.isVerified(),
                from,
                to);
    }

    private <T> NonMatchingVerifiableAttribute<T> mapToNonMatchingVerifiableAttribute(SimpleMdsValue<T> simpleMdsValueOptional) {
        final LocalDate from = Optional.ofNullable(simpleMdsValueOptional.getFrom())
                .map(MatchingDatasetToNonMatchingAttributesMapper::convertJodaDateTimeToJavaLocalDate)
                .orElse(null);

        final LocalDate to = Optional.ofNullable(simpleMdsValueOptional.getTo())
                .map(MatchingDatasetToNonMatchingAttributesMapper::convertJodaDateTimeToJavaLocalDate)
                .orElse(null);

        return new NonMatchingVerifiableAttribute<>(
                simpleMdsValueOptional.getValue(),
                simpleMdsValueOptional.isVerified(),
                from,
                to);
    }

    private List<NonMatchingVerifiableAttribute<NonMatchingAddress>> mapAddresses(List<Address> addresses) {
        return addresses.stream().map(this::mapAddress).sorted(attributeComparator()).collect(Collectors.toList());
    }

    private NonMatchingVerifiableAttribute<NonMatchingAddress> mapAddress(Address input) {
        final NonMatchingAddress transformedAddress = new NonMatchingAddress(
                input.getLines(),
                input.getPostCode().orElse(null),
                input.getInternationalPostCode().orElse(null),
                input.getUPRN().orElse(null));

        final LocalDate from = Optional.ofNullable(input.getFrom())
                .map(MatchingDatasetToNonMatchingAttributesMapper::convertJodaDateTimeToJavaLocalDate)
                .orElse(null);

        final LocalDate to = input.getTo()
                .map(MatchingDatasetToNonMatchingAttributesMapper::convertJodaDateTimeToJavaLocalDate)
                .orElse(null);

        return new NonMatchingVerifiableAttribute<>(
                transformedAddress,
                input.isVerified(),
                from,
                to);
    }

    private static LocalDate convertJodaDateTimeToJavaLocalDate(org.joda.time.DateTime jodaDateTime) {
        return LocalDate.of(
                jodaDateTime.getYear(),
                jodaDateTime.getMonthOfYear(),
                jodaDateTime.getDayOfMonth());
    }

    private static LocalDate convertJodaLocalDateToJavaLocalDate(org.joda.time.LocalDate jodaDate) {
        return LocalDate.of(jodaDate.getYear(), jodaDate.getMonthOfYear(), jodaDate.getDayOfMonth());
    }

    private static SimpleMdsValue<LocalDate> convertWrappedJodaLocalDateToJavaLocalDate(SimpleMdsValue<org.joda.time.LocalDate> wrappedJodaDate) {
        final LocalDate javaLocalDate = convertJodaLocalDateToJavaLocalDate(wrappedJodaDate.getValue());
        return new SimpleMdsValue<>(javaLocalDate, wrappedJodaDate.getFrom(), wrappedJodaDate.getTo(), wrappedJodaDate.isVerified());
    }
}
