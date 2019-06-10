FROM alpine:3.9 as clone

RUN apk --update add --no-cache git
RUN git clone --depth=1 https://github.com/alphagov/verify-saml-libs.git && \
    rm -rf verify-saml-libs/.git

FROM gradle:jdk11

COPY --from=clone /verify-saml-libs/ /verify-saml-libs/
WORKDIR /verify-saml-libs/

CMD [ "./pre-commit.sh" ]
