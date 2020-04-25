FROM messense/rust-musl-cross:armv7-musleabihf AS build

RUN mkdir -p /home/rust/src
WORKDIR /home/rust/src
COPY . /home/rust/src

RUN cargo build --release --features="web-monitor"
RUN musl-strip target/armv7-unknown-linux-musleabihf/release/monitor

FROM alpine as certs

RUN apk update && apk add ca-certificates

FROM busybox:musl

COPY --from=build /home/rust/src/target/armv7-unknown-linux-musleabihf/release/monitor /gardena_bin/monitor

COPY --from=certs /etc/ssl/certs /etc/ssl/certs
ENV SSL_CERT_FILE /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_DIR /etc/ssl/certs
