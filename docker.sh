#!/usr/bin/env bash

set -e

function be_in_directory {
    cd "$( dirname "${BASH_SOURCE[0]}" )"
}

be_in_directory
docker build -t verify-saml-libs .
docker run --rm -it verify-saml-libs "$@"
