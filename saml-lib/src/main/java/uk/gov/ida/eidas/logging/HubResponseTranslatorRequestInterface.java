package uk.gov.ida.eidas.logging;

import java.net.URI;

public interface HubResponseTranslatorRequestInterface {
    String getRequestId();
    URI getDestinationUrl();
}