FROM quay.io/konflux-ci/yq@sha256:2d22666968448e7d6455ca2a32465ca9cfcc7e4676a86ecaa31dbea55fcf9cd1 as yq
FROM registry.redhat.io/openshift4/ose-cli-artifacts-rhel9:v4.17.0-202504091537.p0.g0000b3e.assembly.stream.el9 as oc

FROM registry.access.redhat.com/ubi9/ubi:latest@sha256:a1804302f6f53e04cc1c6b20bc2204d5c9ae6e5a664174b38fbeeb30f7983d4e

COPY --from=yq /usr/bin/yq /usr/bin/yq
COPY --from=oc /usr/bin/oc /usr/bin/oc

RUN dnf -y install git ruby gcc python-unversioned-command python3-devel python3-pip && dnf clean all

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


