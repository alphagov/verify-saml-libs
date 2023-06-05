Verify SAML Libraries 📚
========================

>**GOV.UK Verify has closed**
>
>This repository is out of date and has been archived

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
