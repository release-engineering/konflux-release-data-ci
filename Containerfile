FROM quay.io/konflux-ci/yq@sha256:06518dab2bb28223e141c982c71353e2609d70fe17f6151cb885563602fafda5 as yq

FROM registry.access.redhat.com/ubi9/ubi:latest@sha256:0879eaf704bf508379bdb0f465b8ea184c1ec9f1f40a413422fc17f6d3fb2389

COPY --from=yq /usr/bin/yq /usr/bin/yq

RUN curl -sL "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv5.7.1/kustomize_v5.7.1_linux_amd64.tar.gz" \
    | tar -xz -C /usr/bin kustomize && \
    curl -sL "https://mirror.openshift.com/pub/openshift-v4/amd64/clients/ocp/stable/openshift-client-linux.tar.gz" \
    | tar -xz -C /usr/bin oc kubectl

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


