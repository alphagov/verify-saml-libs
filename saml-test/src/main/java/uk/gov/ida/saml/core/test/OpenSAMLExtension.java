package uk.gov.ida.saml.core.test;

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.runners.model.InitializationError;
import uk.gov.ida.saml.core.IdaSamlBootstrap;

public class OpenSAMLExtension implements BeforeAllCallback {
    @Override
    public void beforeAll(ExtensionContext context) throws InitializationError {
        try {
            IdaSamlBootstrap.bootstrap();
        } catch (IdaSamlBootstrap.BootstrapException e) {
            throw new InitializationError(e);
        }
    }
}
