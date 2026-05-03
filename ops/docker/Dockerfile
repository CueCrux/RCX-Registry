# syntax=docker/dockerfile:1.7
#
# RCX-Registry server image.
# Per CueCrux/CLAUDE.md §9 we prefer Chainguard images. The build stage
# uses the `-dev` variant (has a shell + apk) to compile; the runtime
# stage uses the minimal non-dev wolfi-base.
#
# Free-tier Chainguard images require `:latest` tags — that's accepted.

ARG RUST_VERSION=1.93

FROM cgr.dev/chainguard/wolfi-base:latest AS builder
ARG RUST_VERSION
ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:$PATH

RUN apk add --no-cache build-base curl ca-certificates pkgconf openssl-dev \
 && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- --default-toolchain ${RUST_VERSION} -y --profile minimal \
 && rustup component add --toolchain ${RUST_VERSION} rustfmt

WORKDIR /workspace
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    cargo build --release --bin rcx-registry-server \
 && cp /workspace/target/release/rcx-registry-server /usr/local/bin/rcx-registry-server

FROM cgr.dev/chainguard/wolfi-base:latest AS runtime
RUN apk add --no-cache ca-certificates tini libgcc \
 && addgroup -S rcx && adduser -S -G rcx -h /home/rcx rcx

COPY --from=builder /usr/local/bin/rcx-registry-server /usr/local/bin/rcx-registry-server

USER rcx
WORKDIR /home/rcx
EXPOSE 3030
ENV RCX_REGISTRY_BIND=0.0.0.0:3030 \
    RUST_LOG=info

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/rcx-registry-server"]
