Verify SAML Libraries 📚
========================

[![Build Status](https://travis-ci.org/alphagov/verify-saml-libs.svg?branch=master)](https://travis-ci.org/alphagov/verify-saml-libs)

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
