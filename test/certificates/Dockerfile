FROM alpine:latest

RUN apk update && \
  apk add --no-cache openssl bash && \
  rm -rf "/var/cache/apk/*"

COPY createca.sh createcerts.sh entrypoint.sh /scripts/

ENTRYPOINT [ "bash", "/scripts/entrypoint.sh" ]
