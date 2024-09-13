FROM quay.io/konflux-ci/yq:latest as yq

FROM registry.access.redhat.com/ubi9:latest

COPY --from=yq /usr/bin/yq /usr/bin/yq

RUN dnf -y install tox; dnf clean all

LABEL name="konflux-release-data-ci" \
    summary="Container image for running gitlab ci tasks for konflux-release-data config repo" \
    com.redhat.component="konflux-release-data-ci" \
    description="see summary :D" \
    io.k8s.display-name="konflux-release-data-ci" \
    io.k8s.description="Container image for running gitlab ci tasks for konflux-release-data config repo" \
    io.openshift.tags="oci"

ENTRYPOINT []


