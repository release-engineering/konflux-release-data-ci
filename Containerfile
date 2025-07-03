FROM quay.io/konflux-ci/yq@sha256:15d0238843d954ee78c9c190705eb8b36f6e52c31434183c37d99a80841a635a as yq
FROM registry.redhat.io/openshift4/ose-cli-artifacts-rhel9:v4.17.0-202504091537.p0.g0000b3e.assembly.stream.el9 as oc

FROM registry.access.redhat.com/ubi9/ubi:latest@sha256:2e4eebec441e8bbc3459fcc83ddee0f7d3cfd219097b4110a37d7ff4fe0ff2e9

COPY --from=yq /usr/bin/yq /usr/bin/yq
COPY --from=oc /usr/bin/oc /usr/bin/oc

RUN dnf -y install git \
    ruby \
    gcc \
    python-unversioned-command \
    python3-devel \
    python3-pip \
    diffutils \
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


