package uk.gov.ida.saml.security.signature;

import io.prometheus.client.Counter;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.Criterion;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import uk.gov.ida.saml.core.test.TestCertificateStrings;
import uk.gov.ida.saml.core.test.TestCredentialFactory;
import uk.gov.ida.saml.security.saml.OpenSAMLMockitoRunner;
import uk.gov.ida.saml.security.saml.builders.AssertionBuilder;
import uk.gov.ida.saml.security.saml.builders.SignatureBuilder;
import java.util.Arrays;
import java.util.Collections;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(OpenSAMLMockitoRunner.class)
public class OutgoingKeySignatureTrustEngineTest {

    @Test
    public void shouldVerifyIdpWithAValidSigningCertificate() throws Exception {
        final Credential outgoingSigningCredential = new TestCredentialFactory(
                TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT,
                TestCertificateStrings.HUB_TEST_PRIVATE_SIGNING_KEY
        ).getSigningCredential();
        final OutgoingKeySignatureTrustEngine trustEngine = spy(new OutgoingKeySignatureTrustEngine(
                new StaticCredentialResolver(
                        Collections.singletonList(outgoingSigningCredential)
                ),
                DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver()
        ));
        final Credential incomingSigningCredential = new TestCredentialFactory(TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT, TestCertificateStrings.HUB_TEST_PRIVATE_SIGNING_KEY).getSigningCredential();
        final Assertion assertion = AssertionBuilder.anAssertion().withSignature(SignatureBuilder.aSignature().withSigningCredential(incomingSigningCredential).build()).build();
        final CriteriaSet trustBasisCriteria = new CriteriaSet();

        trustBasisCriteria.add(mock(Criterion.class));

        assertThat(trustEngine.doValidate(assertion.getSignature(), trustBasisCriteria)).isTrue();
        verify(trustEngine, never()).getOutgoingSignatureVerifyingErrorCounter();
    }

    @Test
    public void shouldSendErrorCounterValidatingWithOutgoingSigningCertificate() throws Exception {
        final Credential incomingSigningCredential = new TestCredentialFactory(
                TestCertificateStrings.HUB_TEST_SECONDARY_PUBLIC_SIGNING_CERT,
                TestCertificateStrings.HUB_TEST_PRIVATE_SECONDARY_SIGNING_KEY
        ).getSigningCredential();
        final Credential outgoingSigningCredential = new TestCredentialFactory(
                TestCertificateStrings.HUB_TEST_PUBLIC_SIGNING_CERT,
                TestCertificateStrings.HUB_TEST_PRIVATE_SIGNING_KEY
        ).getSigningCredential();
        final OutgoingKeySignatureTrustEngine trustEngine = spy(new OutgoingKeySignatureTrustEngine(
                new StaticCredentialResolver(
                        Arrays.asList(incomingSigningCredential, outgoingSigningCredential)
                ),
                DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver()
        ));
        final CriteriaSet trustBasisCriteria = new CriteriaSet();
        final Counter outgoingSignatureVerifyingErrorCounter = mock(Counter.class);
        final Counter.Child childCounter = mock(Counter.Child.class);
        final Assertion outgoing_assertion = AssertionBuilder.anAssertion().withSignature(SignatureBuilder.aSignature().withSigningCredential(outgoingSigningCredential).build()).build();

        trustBasisCriteria.add(mock(Criterion.class));
        
        doReturn(outgoingSignatureVerifyingErrorCounter).when(trustEngine).getOutgoingSignatureVerifyingErrorCounter();
        when(outgoingSignatureVerifyingErrorCounter.labels("verification_failed")).thenReturn(childCounter);
        doNothing().when(childCounter).inc();
        assertThat(trustEngine.doValidate(outgoing_assertion.getSignature(), trustBasisCriteria)).isTrue();
        verify(trustEngine).getOutgoingSignatureVerifyingErrorCounter();
        verify(childCounter).inc();
    }
}
