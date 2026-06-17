# Makefile for KLLDAP (lldap-with-kerberos)
#
# Clean release build targets.
# - prepare-release          → Native tarball build
# - prepare-release-docker   → Reproducible AlmaLinux tarball build (recommended)
# - docker-build             → Build multi-arch Docker image (amd64 + arm64 by default)

.PHONY: prepare-release prepare-release-docker docker-build clean

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
		--tag aelieth/klldap:latest \
		--tag aelieth/klldap:0.7.2 \
		--push .

# Quick cleanup of generated tarballs
clean:
	rm -f lldap-*-glibc-*.tar.gz
