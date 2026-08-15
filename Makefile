# Makefile for KLLDAP (lldap-with-kerberos)
#
# Clean release build targets.
# - prepare-release          → Native tarball build
# - prepare-release-docker   → Reproducible AlmaLinux tarball build (recommended)
# - docker-build             → Build multi-arch Docker image (amd64 + arm64 by default)
# - test                     → Local test image (klldap-test) from this tree, native CPU
# - test-run                 → Run klldap-test with local volumes and test secrets

.PHONY: prepare-release prepare-release-docker docker-build test test-run clean

# Single-sourced from [workspace.package] in Cargo.toml (first version line in the file).
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)

# Native prepare-release (run directly — needs Rust, cross, Docker, and system deps like krb5-devel)
prepare-release:
	./prepare-release.sh

# Fully Dockerized release build (AlmaLinux 10 base).
# Builds a reproducible AlmaLinux container with:
#   - krb5-devel (consistent with runtime image)
#   - cross (Docker socket mounted so it can spawn the armv7 build container)
#   - wasm-pack
# Then runs prepare-release.sh inside it.
#
# Output: lldap-x86_64-glibc-*.tar.gz and lldap-armv7-glibc-*.tar.gz
#
# Note: Uses --privileged + Docker socket (standard for cross-in-cross).
# Only run on trusted builders / CI.
prepare-release-docker:
	docker buildx build \
		--file Dockerfile.release \
		--tag klldap/release-builder:latest \
		--load .
	docker run --rm \
		--privileged \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v "$(PWD)":/work \
		-w /work \
		klldap/release-builder:latest \
		./prepare-release.sh

# Build the main multi-stage KLLDAP Docker image for multiple architectures.
# Supports a wide variety of processors (x86_64 + arm64 by default).
#
# Default platforms: linux/amd64,linux/arm64
# Override example: make docker-build PLATFORMS=linux/amd64
#
# Note: This builds the full runtime image with Kerberos support.
# For maximum x86_64 compatibility inside the image, we can add
# RUSTFLAGS later if needed (similar to the tarball build).
PLATFORMS ?= linux/amd64/v2,linux/arm64

docker-build:
	docker buildx build \
		--file Dockerfile \
		--platform $(PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		--tag aelieth/klldap:latest \
		--tag aelieth/klldap:$(VERSION) \
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
		-p 88:88/tcp -p 88:88/udp -p 749:749/tcp \
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
# - safety        → the pre-commit dance: fmt, build, test, clippy, schema drift
# - gate          → build the test image and run the full container gate
# - gate-fast     → run the gate against the existing klldap-test image
# - gate-postgres → gate with a gate-managed postgres:16 backend
# - gate-phase    → run selected phases, e.g. make gate-phase PHASE=kerberos
.PHONY: safety gate gate-fast gate-postgres gate-phase test-kdc

safety:
	cargo fmt --all
	cargo build --workspace
	cargo test --workspace
	cargo clippy --tests --all -- -D warnings
	./export_schema.sh
	git diff --exit-code schema.graphql

gate: test
	gate/run-gate.sh

gate-fast:
	gate/run-gate.sh

gate-postgres:
	GATE_DB=postgres gate/run-gate.sh

gate-phase:
	GATE_PHASES="$(PHASE)" gate/run-gate.sh

test-kdc:
	gate/kdc-sandbox.sh cargo test -p lldap-kerberos -- --ignored --nocapture

# Quick cleanup of generated tarballs
clean:
	rm -f lldap-*-glibc-*.tar.gz
