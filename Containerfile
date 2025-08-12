FROM quay.io/konflux-ci/yq@sha256:15d0238843d954ee78c9c190705eb8b36f6e52c31434183c37d99a80841a635a as yq
FROM registry.redhat.io/openshift4/ose-cli-artifacts-rhel9:v4.17.0-202504091537.p0.g0000b3e.assembly.stream.el9 as oc

# Build stage for RBAC validator
FROM registry.access.redhat.com/ubi9/go-toolset:1.24.4-1754467841@sha256:3f552f246b4bd5bdfb4da0812085d381d00d3625769baecaed58c2667d344e5c as go-builder

# Copy tools directory and build the binary
COPY --chown=default tools/ /workspace/tools/
WORKDIR /workspace/tools
RUN go mod download && \
    go build -o rbac-validator rbac-validator.go

# Main stage
FROM registry.access.redhat.com/ubi9/ubi:latest@sha256:8851294389a8641bd6efcd60f615c69e54fb0e2216ec8259448b35e3d9a11b06

COPY --from=yq /usr/bin/yq /usr/bin/yq
COPY --from=oc /usr/bin/oc /usr/bin/oc
COPY --from=go-builder /workspace/tools/rbac-validator /usr/local/bin/rbac-validator

# Ensure the binary is executable
RUN chmod +x /usr/local/bin/rbac-validator

RUN dnf -y install git \
    ruby \
    gcc \
    python-unversioned-command \
    python3-devel \
    python3-pip \
    diffutils \
    krb5-devel \
    && dnf clean all

COPY requirements.txt ./

RUN pip3 install -r requirements.txt

# Because Cachi2 doesn't support ruby, we've got to gem install it for now
# Can look into building it from source later, although without prefetch
# not much more secure

# Currently doing the gem install is breaking syft
# This should work with ruby prefetch but that's still a preview
# RUN gem install mdl

LABEL name="konflux-release-data-ci" \
    version="0.2" \
    release="1" \
    summary="Container image for running gitlab ci tasks for konflux-release-data config repo" \
    com.redhat.component="konflux-release-data-ci" \
    description="see summary :D" \
    distribution-scope="restricted" \
    url="https://github.com/release-engineering/konflux-release-data-ci/tree/main" \
    vendor="Red Hat, Inc." \
    io.k8s.display-name="konflux-release-data-ci" \
    io.k8s.description="Container image for running gitlab ci tasks for konflux-release-data config repo" \
    io.openshift.tags="oci"

ENTRYPOINT []


