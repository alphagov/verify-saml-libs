[![Codacy Badge](https://api.codacy.com/project/badge/Grade/580d123edf8e4ced80eb40e5aa08ef2f)](https://www.codacy.com/app/alphagov/verify-saml-libs?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=alphagov/verify-saml-libs&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/580d123edf8e4ced80eb40e5aa08ef2f)](https://www.codacy.com/app/alphagov/verify-saml-libs?utm_source=github.com&utm_medium=referral&utm_content=alphagov/verify-saml-libs&utm_campaign=Badge_Coverage)

Verify SAML Libraries 📚
========================

The `verify-saml-lib` library contains most of the shared SAML code used by Verify's components. The `verify-saml-test` library contains useful builders and factories for tests.

`verify-saml-lib` was previously split into:

* saml-extensions
* saml-security
* saml-utils
* saml-serializers
* saml-metadata-bindings
* trust-anchor

`verify-saml-test` was previously split into:

* saml-test-utils
* saml-metadata-bindings-test

### Building the project

`./gradlew clean build`

## Licence

[MIT Licence](LICENCE)

This code is provided for informational purposes only and is not yet intended for use outside GOV.UK Verify
