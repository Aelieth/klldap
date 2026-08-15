# Use almalinux minimal for builder and runtime (glibc consistency + reliable bindgen)
FROM quay.io/almalinuxorg/10-minimal AS chef

# Install build deps (Fedora packages)
RUN microdnf install -y --assumeyes \
    shadow-utils pkgconf openssl-devel gcc make perl curl gzip krb5-devel clang llvm \
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
    -p lldap_set_password \
    -p lldap-kerberos

# Install wasm tools
RUN cargo install wasm-pack --locked
RUN cargo install wasm-bindgen-cli --locked

# Build the frontend
RUN ./app/build.sh

# Final runtime image
FROM quay.io/almalinuxorg/10-minimal

# Gosu for privilege drop
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
    gosu nobody true && \
    microdnf clean all

# Recreate lldap user
RUN groupadd -g 1000 lldap && \
    useradd -u 1000 -g lldap -d /app -s /bin/bash lldap && \
    chown -R lldap:lldap /app

# Runtime deps (Kerberos + LLDAP needs)
RUN microdnf install -y --assumeyes \
    tzdata bash openssl cyrus-sasl-gssapi krb5-server krb5-libs krb5-workstation openldap-clients procps-ng ca-certificates \
    && microdnf clean all

# Pre-create persistent directories with correct ownership
RUN mkdir -p /data/cert /var/kerberos/krb5kdc /var/log/krb5 && \
    chown -R lldap:lldap /data /var/kerberos /var/log/krb5

WORKDIR /app

# Copy binaries and frontend assets
COPY --from=builder --chown=lldap:lldap /app/target/release/lldap /app/target/release/lldap_migration_tool /app/target/release/lldap_set_password /app/
COPY --from=builder --chown=lldap:lldap /app/app/static /app/app/static
COPY --from=builder --chown=lldap:lldap /app/app/pkg /app/app/pkg
COPY --from=builder --chown=lldap:lldap /app/app/index.html /app/app/index.html
COPY --from=builder --chown=lldap:lldap /app/target/release/kerberos_manager /app/

# Copy configs and templates
COPY --chown=lldap:lldap lldap_config.docker_template.toml /app/
COPY --chown=lldap:lldap scripts/bootstrap.sh /app/
COPY --chown=lldap:lldap kerberos/kerberos_config.template.toml /app/kerberos_config.template.toml
COPY --chown=lldap:lldap kerberos/krb5.template.conf /app/krb5.template.conf
COPY --chown=lldap:lldap kerberos/kdc.template.conf /app/kdc.template.conf
COPY --chown=lldap:lldap kerberos/kadm5.template.acl /app/kadm5.template.acl

# Combined entrypoint
COPY --chown=lldap:lldap entrypoint.sh /entrypoint.sh
COPY --chown=lldap:lldap start-lldap.sh /start-lldap.sh
RUN chmod +x /entrypoint.sh
RUN chmod +x /start-lldap.sh

# Volumes for persistence
VOLUME /data /var/kerberos/krb5kdc

# Ports
EXPOSE 3890 17170 88/tcp 88/udp 749/tcp

# UID/GID can be overridden at runtime for rootless deployments (e.g. podman rootless,
# docker --user, or kubernetes securityContext) — prefer LLDAP_UID/LLDAP_GID; the legacy
# UID/GID names are still honored (read via printenv, immune to bash builds that reset
# $UID to a readonly builtin). Default matches the lldap user created below (1000:1000).
# The named "lldap" user/group stays: it is the ownership fallback when LLDAP_UID/LLDAP_GID
# are unset.
ENV UID=1000 GID=1000 LLDAP_UID=1000 LLDAP_GID=1000
# The KDC is part of this image: the healthcheck covers it and directory writes wait for it
# to come up after boot.
ENV LLDAP_HEALTHCHECK_OPTIONS__KERBEROS=true

# Entry & health — pass --config-file explicitly (like upstream LLDAP) so the prepared
# /data/lldap_config.toml (with key_seed, database_url pointing at the volume, etc.) is
# always used for both the long-lived server and healthchecks. The --kerberos leg makes
# a dead KDC (or missing admin keytab) turn the container unhealthy; the start period
# covers LLDAP boot + KDC bootstrap on first run.
ENTRYPOINT ["/entrypoint.sh"]
CMD ["run", "--config-file", "/data/lldap_config.toml"]
HEALTHCHECK --start-period=90s --interval=30s --retries=3 \
    CMD ["/app/lldap", "healthcheck", "--config-file", "/data/lldap_config.toml", "--kerberos"]

ARG VERSION=dev
LABEL maintainer="Aelieth <https://github.com/Aelieth>" \
      version="${VERSION}" \
      description="KLLDAP"
