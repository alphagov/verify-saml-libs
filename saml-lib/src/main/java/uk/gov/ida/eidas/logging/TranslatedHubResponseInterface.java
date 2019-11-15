package uk.gov.ida.eidas.logging;

import uk.gov.ida.verifyserviceprovider.dto.NonMatchingAttributes;

public interface TranslatedHubResponseInterface {
    String getPid();
    NonMatchingAttributes getAttributes();
}
