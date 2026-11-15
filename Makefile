# Makefile for KLLDAP (lldap-with-kerberos)
#
# Clean release build targets.
# - prepare-release          → Native tarball build
# - prepare-release-docker   → Reproducible AlmaLinux tarball build (recommended)
# - docker-build             → Build and push the multi-arch images, default and rootless (amd64 + arm64)
# - test                     → Local test image (klldap-test) from this tree, native CPU
# - test-run                 → Run klldap-test with local volumes and test secrets

.PHONY: prepare-release prepare-release-docker docker-build test test-run clean

# Single-sourced from [workspace.package] in Cargo.toml (first version line in the file).
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

# Native prepare-release (run directly — needs Rust, wasm-pack and gzip)
prepare-release:
	./prepare-release.sh

# Fully Dockerized release build (AlmaLinux 10 base), one builder per platform.
# linux/amd64/v2 builds the x86_64 tarball and the web app: x86-64-v2 for rustc and gcc, by
# the v2 base's compiler and prepare-release.sh's own flags, which it then checks in the binary;
# linux/arm64 then
# builds the aarch64 tarball (under qemu emulation on an x86_64 host), reusing the same
# tree's web files (SKIP_FRONTEND=1 refuses if they are missing).
#
# Output: lldap-x86_64-glibc-*.tar.gz and lldap-aarch64-glibc-*.tar.gz (64-bit only).
#
# Note: no --privileged and no Docker socket; the build needs neither.
prepare-release-docker:
	docker buildx build --platform linux/amd64/v2 \
		--file Dockerfile.release \
		--tag klldap/release-builder:amd64 \
		--load .
	docker run --rm --platform linux/amd64/v2 \
		-v "$(PWD)":/work \
		-w /work \
		klldap/release-builder:amd64 \
		./prepare-release.sh
	docker buildx build --platform linux/arm64 \
		--file Dockerfile.release \
		--tag klldap/release-builder:arm64 \
		--load .
	docker run --rm --platform linux/arm64 \
		-e SKIP_FRONTEND=1 \
		-v "$(PWD)":/work \
		-w /work \
		klldap/release-builder:arm64 \
		./prepare-release.sh

# Build the main multi-stage KLLDAP Docker image for multiple architectures.
# Supports a wide variety of processors (x86_64 + arm64 by default).
#
# Default platforms: linux/amd64/v2,linux/arm64
# Override example: make docker-build PLATFORMS=linux/amd64/v2
#
# Note: This builds the full runtime image with Kerberos support, twice:
# the default image and the rootless image (the Dockerfile's `rootless`
# target), named with a `-rootless` suffix as upstream LLDAP names its own.
#
# It pushes :$(VERSION) and :$(VERSION)-rootless only. PROMOTE=1 on the make
# command line (make docker-build PROMOTE=1) also pushes :latest and
# :latest-rootless; PROMOTE from the environment does not count.
PLATFORMS ?= linux/amd64/v2,linux/arm64
PROMOTED = $(and $(filter 1,$(PROMOTE)),$(filter command line,$(origin PROMOTE)))

docker-build:
	docker buildx build \
		--file Dockerfile \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		--tag aelieth/klldap:$(VERSION) $(if $(PROMOTED),--tag aelieth/klldap:latest) \
		--push .
	docker buildx build \
		--file Dockerfile \
		--target rootless \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		--tag aelieth/klldap:$(VERSION)-rootless $(if $(PROMOTED),--tag aelieth/klldap:latest-rootless) \
		--push .

# Local test image from this tree. Tag is just klldap-test (no version).
# Compiles with target-cpu=native so rustc can use this machine's ISA.
# Host-arch only, loaded into the local docker (not pushed).
#
#   make test
#   docker run --rm -p 3890:3890 -p 17170:17170 klldap-test
test:
	docker build \
		--file Dockerfile \
		--build-arg VERSION=$(VERSION)-test \
		--build-arg CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=native" \
		--build-arg CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=native" \
		--target rootless \
		--tag klldap-test-rootless \
		.
	docker build \
		--file Dockerfile \
		--build-arg VERSION=$(VERSION)-test \
		--build-arg CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=native" \
		--build-arg CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=native" \
		--target default \
		--tag klldap-test \
		.

# Run the local test image. Requires `make test` first.
# Override secrets/base DN with the same LLDAP_* env vars you would pass to docker.
LLDAP_JWT_SECRET ?= testdev-jwt-secret-not-for-production
LLDAP_KEY_SEED ?= testdev-key-seed-not-for-production
LLDAP_LDAP_BASE_DN ?= dc=example,dc=com
LLDAP_LDAP_USER_PASS ?= adminadmin
test-run:
	@docker image inspect klldap-test >/dev/null 2>&1 || { \
		echo "Image klldap-test not found. Run: make test"; exit 1; }
	-docker rm -f klldap-test >/dev/null 2>&1
	docker run -d --name klldap-test \
		-p 3890:3890 -p 17170:17170 \
		-p 88:1088/tcp -p 88:1088/udp \
		-e LLDAP_JWT_SECRET="$(LLDAP_JWT_SECRET)" \
		-e LLDAP_KEY_SEED="$(LLDAP_KEY_SEED)" \
		-e LLDAP_LDAP_BASE_DN="$(LLDAP_LDAP_BASE_DN)" \
		-e LLDAP_LDAP_USER_PASS="$(LLDAP_LDAP_USER_PASS)" \
		-e LLDAP_DATABASE_URL="sqlite:////data/users.db?mode=rwc" \
		-v klldap-test-data:/data \
		-v klldap-test-kdc:/var/kerberos/krb5kdc \
		klldap-test
	@echo "UI:   http://127.0.0.1:17170  (admin / $(LLDAP_LDAP_USER_PASS))"
	@echo "logs: docker logs -f klldap-test"

# ---- Verification ----
# - safety        → the pre-commit dance: fmt, build, test, clippy, cargo deny, schema drift
# - advisories    → cargo deny check advisories, before a tag or release
# - gate          → build the test image and run the full container gate
# - gate-fast     → run the gate against the existing klldap-test image
# - gate-postgres → gate with a gate-managed postgres:16 backend
# - lane-mysql    → ignored cargo lane on a scratch mysql:9.7
# - lane-mariadb  → the same lane on a scratch mariadb:12.3
# - gate-rootless → gate (SQLite) on the -rootless image
# - gate-phase    → run selected phases, e.g. make gate-phase PHASE=kerberos
.PHONY: safety advisories gate gate-fast gate-postgres lane-mysql lane-mariadb gate-rootless gate-phase

safety:
	cargo fmt --all
	cargo build --workspace
	cargo test --workspace
	cargo clippy --tests --all -- -D warnings
	cargo deny check licenses sources
	./export_schema.sh
	git diff --exit-code schema.graphql

advisories:
	cargo deny check advisories

gate: test
	gate/run-gate.sh

gate-fast:
	gate/run-gate.sh

gate-postgres:
	GATE_DB=postgres gate/run-gate.sh

lane-mysql:
	GATE_MYSQL_FLAVOR=mysql gate/mysql-lane.sh

lane-mariadb:
	GATE_MYSQL_FLAVOR=mariadb gate/mysql-lane.sh

gate-rootless: test
	GATE_IMAGE=klldap-test-rootless GATE_ROOTLESS=1 gate/run-gate.sh

gate-phase:
	GATE_PHASES="$(PHASE)" gate/run-gate.sh

# Quick cleanup of generated tarballs
clean:
	rm -f lldap-*-glibc-*.tar.gz
