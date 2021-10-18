package uk.gov.ida.saml.security.signature;

import io.prometheus.client.Counter;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;
import uk.gov.ida.saml.security.saml.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.security.saml.builders.AssertionBuilder;
import uk.gov.ida.saml.security.saml.builders.SignatureBuilder;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@RunWith(OpenSAMLMockitoRunner.class)
public class OutgoingKeySignatureTrustEngineTest {
    @Mock
    private Counter outgoingSignatureVerifyingErrorCounter;

    @Test
    public void shouldVerifyIdpWithAValidSigningCertificate() throws Exception {
        setFinalStatic(OutgoingKeySignatureTrustEngine.class.getDeclaredField("outgoingSignatureVerifyingErrorCounter"), outgoingSignatureVerifyingErrorCounter);

        final Credential outgoingSigningCredential = new TestCredentialFactory(
                TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT,
                TestCertificateStrings.HUB_TEST_PRIVATE_SIGNING_KEY
        ).getSigningCredential();
        final OutgoingKeySignatureTrustEngine trustEngine = new OutgoingKeySignatureTrustEngine(
                new StaticCredentialResolver(
                        Collections.singletonList(outgoingSigningCredential)
                ),
                DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver()
        );
        final Credential incomingSigningCredential = new TestCredentialFactory(TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT, TestCertificateStrings.HUB_TEST_PRIVATE_SIGNING_KEY).getSigningCredential();
        final Assertion assertion = AssertionBuilder.anAssertion().withSignature(SignatureBuilder.aSignature().withSigningCredential(incomingSigningCredential).build()).build();
        final CriteriaSet trustBasisCriteria = new CriteriaSet();

        trustBasisCriteria.add(mock(Criterion.class));

        assertThat(trustEngine.doValidate(assertion.getSignature(), trustBasisCriteria)).isTrue();
        verifyNoInteractions(outgoingSignatureVerifyingErrorCounter);
    }

    @Test
    public void shouldSendErrorCounterValidatingWithOutgoingSigningCertificate() throws Exception {

        setFinalStatic(OutgoingKeySignatureTrustEngine.class.getDeclaredField("outgoingSignatureVerifyingErrorCounter"), outgoingSignatureVerifyingErrorCounter);

        final Credential incomingSigningCredential = new TestCredentialFactory(
                TestCertificateStrings.HUB_TEST_SECONDARY_PUBLIC_SIGNING_CERT,
                TestCertificateStrings.HUB_TEST_PRIVATE_SECONDARY_SIGNING_KEY
        ).getSigningCredential();
        final Credential outgoingSigningCredential = new TestCredentialFactory(
                TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT,
                TestCertificateStrings.HUB_TEST_PRIVATE_SIGNING_KEY
        ).getSigningCredential();
        final OutgoingKeySignatureTrustEngine trustEngine = new OutgoingKeySignatureTrustEngine(
                new StaticCredentialResolver(
                        Arrays.asList(incomingSigningCredential, outgoingSigningCredential)
                ),
                DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver()
        );
        final CriteriaSet trustBasisCriteria = new CriteriaSet();
        final Assertion outgoing_assertion = AssertionBuilder.anAssertion().withSignature(SignatureBuilder.aSignature().withSigningCredential(outgoingSigningCredential).build()).build();

        trustBasisCriteria.add(mock(Criterion.class));
        
        assertThat(trustEngine.doValidate(outgoing_assertion.getSignature(), trustBasisCriteria)).isTrue();
        verify(outgoingSignatureVerifyingErrorCounter).inc();
    }

    private static void setFinalStatic(Field field, Object newValue) throws Exception {
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        field.set(null, newValue);
    }
}
