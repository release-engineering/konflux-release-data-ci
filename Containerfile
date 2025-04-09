FROM quay.io/konflux-ci/yq@sha256:4ea9ee652a035c341d00424ff6ebaf757f4b9391e016d3fdb542981bf0f537ef as yq

FROM registry.access.redhat.com/ubi9/ubi:latest@sha256:ea57285741f007e83f2ee20423c20b0cbcce0b59cc3da027c671692cc7efe4dd

COPY --from=yq /usr/bin/yq /usr/bin/yq

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


