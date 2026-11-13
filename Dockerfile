# Use almalinux minimal for builder and runtime (one glibc for both)
FROM quay.io/almalinuxorg/10-minimal AS chef

# Install build deps (Fedora packages)
RUN microdnf install -y --assumeyes \
    shadow-utils pkgconf openssl-devel gcc make perl curl gzip \
    && microdnf clean all

# Create /app directory and lldap user (home = /app)
RUN mkdir -p /app && \
    groupadd -g 1000 lldap && \
    useradd -u 1000 -g lldap -d /app -s /bin/bash lldap && \
    chown -R lldap:lldap /app

USER lldap
WORKDIR /app

# Install latest Rust/Cargo via rustup as lldap user
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable

# Add Cargo to PATH
ENV PATH="/app/.cargo/bin:${PATH}"

# Verify Rust/Cargo
RUN rustc --version && cargo --version

# Portable x86-64 baseline for release images. `make test` overrides with native.
ARG CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=x86-64"
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=$CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS
ARG CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS=$CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS

# Install cargo-chef for dependency caching, add wasm target
RUN cargo install cargo-chef && rustup target add wasm32-unknown-unknown

FROM chef AS planner
COPY --chown=lldap:lldap . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY --chown=lldap:lldap . .

RUN cargo build --release \
    -p lldap \
    -p lldap_migration_tool \
    -p lldap_set_password

# Install wasm tools
RUN cargo install wasm-pack --locked
RUN cargo install wasm-bindgen-cli --locked

# Build the frontend
RUN ./app/build.sh

# Runtime base, shared by the default and the rootless image (upstream's debian-base)
FROM quay.io/almalinuxorg/10-minimal AS runtime

# Recreate lldap user (shadow-utils provides groupadd and useradd). useradd makes its home /app
# 0700; upstream's /app is readable by all, which the -rootless image needs under another user.
RUN microdnf install -y --assumeyes shadow-utils && microdnf clean all && \
    groupadd -g 1000 lldap && \
    useradd -u 1000 -g lldap -d /app -s /bin/bash lldap && \
    chown -R lldap:lldap /app && \
    chmod 0755 /app

# Runtime deps: Kerberos and LDAP client tools for docker exec
RUN microdnf install -y --assumeyes \
    tzdata bash openssl cyrus-sasl-gssapi krb5-libs krb5-workstation openldap-clients procps-ng ca-certificates \
    && microdnf clean all
# tini as init, as upstream's image has it. AlmaLinux 10 does not package it, so the release
# binary is checked against its signing key, as gosu's is: the README names subkey
# 595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7, fetched by its primary key from keys.openpgp.org.
ENV TINI_VERSION=v0.19.0
RUN microdnf install -y --assumeyes wget gnupg && \
    arch="$(uname -m)" && \
    case "${arch}" in \
        x86_64) tiniArch='amd64' ;; \
        aarch64) tiniArch='arm64' ;; \
        *) echo >&2 "error: unsupported architecture: '${arch}'"; exit 1 ;; \
    esac && \
    wget -O /usr/local/bin/tini "https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static-${tiniArch}" && \
    wget -O /usr/local/bin/tini.asc "https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static-${tiniArch}.asc" && \
    export GNUPGHOME="$(mktemp -d)" && \
    gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys 6380DC428747F6C393FEACA59A84159D7001A4E5 && \
    gpg --batch --status-fd 1 --verify /usr/local/bin/tini.asc /usr/local/bin/tini \
        | grep -q '^\[GNUPG:\] VALIDSIG 595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7 ' && \
    gpgconf --kill all && \
    rm -rf "$GNUPGHOME" /usr/local/bin/tini.asc && \
    chmod +x /usr/local/bin/tini && \
    tini --version && \
    microdnf clean all

# Pre-create persistent directories with correct ownership
RUN mkdir -p /data/cert /var/kerberos/krb5kdc && \
    chown -R lldap:lldap /data /var/kerberos

WORKDIR /app

# Copy binaries and frontend assets
COPY --from=builder --chown=lldap:lldap /app/target/release/lldap /app/target/release/lldap_migration_tool /app/target/release/lldap_set_password /app/
COPY --from=builder --chown=lldap:lldap /app/app/static /app/app/static
COPY --from=builder --chown=lldap:lldap /app/app/pkg /app/app/pkg
COPY --from=builder --chown=lldap:lldap /app/app/index.html /app/app/index.html

# Copy configs and templates
COPY --chown=lldap:lldap lldap_config.docker_template.toml /app/
COPY --chown=lldap:lldap scripts/bootstrap.sh /app/

# Volumes for persistence
VOLUME /data /var/kerberos/krb5kdc

# Ports
EXPOSE 3890 17170 1088/tcp 1088/udp

# UID and GID choose the server's user, as upstream's do; KLLDAP 0.7.2's LLDAP_UID and
# LLDAP_GID still work and win when set. The entrypoint reads them with printenv.
ENV UID=1000 GID=1000
# The realm runs inside the server; client tools in the container read the krb5.conf it writes.
# The KDC listens on 1088 and kadmin on 127.0.0.1:1749 (the code's defaults): publish 88:1088.
# The code's paths are relative to the working directory, as upstream's are; the image keeps them
# where 0.7.2 had them, which a 0.7.2 config does not name.
ENV KRB5_CONFIG=/data/krb5.conf \
    LLDAP_KERBEROS_OPTIONS__DATA_DIR=/var/kerberos/krb5kdc \
    LLDAP_KERBEROS_OPTIONS__ADMIN_KEYTAB=/data/kadm5.keytab \
    LLDAP_KEYCLOAK_OPTIONS__KEYTAB=/data/keytab/keycloak-http.keytab \
    LLDAP_KERBEROS_OPTIONS__CLIENT_CONFIG=/data/krb5.conf \
    LLDAP_KEYCLOAK_OPTIONS__CONFIG_FILE=/data/keycloak_config.toml

# Entry & health — pass --config-file explicitly (like upstream LLDAP) so the prepared
# /data/lldap_config.toml (with key_seed, database_url pointing at the volume, etc.) is
# always used for both the long-lived server and healthchecks. With Kerberos enabled, a
# realm that is not serving turns the container unhealthy.
ENTRYPOINT ["tini", "--", "/docker-entrypoint.sh"]
CMD ["run", "--config-file", "/data/lldap_config.toml"]
HEALTHCHECK --start-period=90s --interval=30s --retries=3 \
    CMD ["/app/lldap", "healthcheck", "--config-file", "/data/lldap_config.toml"]

ARG VERSION=dev
LABEL maintainer="Aelieth <https://github.com/Aelieth>" \
      version="${VERSION}" \
      description="KLLDAP" \
      org.opencontainers.image.licenses="GPL-3.0-only"

# Rootless image (upstream's -rootless): the server runs as lldap from the start.
FROM runtime AS rootless
COPY --chown=lldap:lldap docker-entrypoint-rootless.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
USER lldap

# Default image, last so a plain build gives it: a root start, ownership repair, then gosu.
FROM runtime AS default
ENV GOSU_VERSION=1.17
RUN microdnf install -y --assumeyes ca-certificates wget gnupg && \
    arch="$(uname -m)" && \
    case "${arch}" in \
        x86_64) gosuArch='amd64' ;; \
        aarch64) gosuArch='arm64' ;; \
        *) echo >&2 "error: unsupported architecture: '${arch}'"; exit 1 ;; \
    esac && \
    wget -O /usr/local/bin/gosu "https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${gosuArch}" && \
    wget -O /usr/local/bin/gosu.asc "https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-${gosuArch}.asc" && \
    export GNUPGHOME="$(mktemp -d)" && \
    gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4 && \
    gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu && \
    gpgconf --kill all && \
    rm -rf "$GNUPGHOME" /usr/local/bin/gosu.asc && \
    chmod +x /usr/local/bin/gosu && \
    gosu --version && \
    gosu nobody true && \
    microdnf clean all
COPY --chown=lldap:lldap docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
