#!/bin/bash

install_container_deps() {
    source ./src/script/run-make.sh
    # set JENKINS_HOME in order to have the build container look as much
    # like an existing jenkins build environment as possible
    export JENKINS_HOME=/ceph
    prepare
}

dnf_clean() {
    if [ "${CLEAN_DNF}" != no ]; then
        dnf clean all
        rm -rf /var/cache/dnf/*
    fi
}

set -e
export LOCALE=C
cd ${CEPH_CTR_SRC}

# If DISTRO_KIND is not already set, derive it from the container's os-release.
if [ -z "$DISTRO_KIND" ]; then
    . /etc/os-release
    DISTRO_KIND="${ID}:${VERSION_ID}"
fi

# Execute a container setup process, installing the packges needed to build
# ceph for the given <branch>~<distro_kind> pair. Some distros need extra
# tools in the container image vs. vm hosts or extra tools needed to build
# packages etc.
case "${CEPH_BASE_BRANCH}~${DISTRO_KIND}" in
    *~*centos*8)
        dnf install -y java-1.8.0-openjdk-headless /usr/bin/{rpmbuild,wget,curl} \
            awscli s3cmd iproute
        install_container_deps
        dnf_clean
    ;;
    # EL-ish, 9+
    *~*centos*|*~fedora*|*~rocky*|*~alma*)
        dnf install -y /usr/bin/{rpmbuild,wget,curl} awscli s3cmd iproute
        install_container_deps
        dnf_clean
    ;;
    *~*ubuntu*|*~*debian*)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends \
            wget reprepro curl software-properties-common \
            lksctp-tools libsctp-dev protobuf-compiler ragel libc-ares-dev \
            iproute2 s3cmd unzip
        # awscli is no longer packaged on recent Ubuntu releases; use the
        # official AWS CLI v2 installer from amazon.
        awscli_arch="$(uname -m)"
        curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-${awscli_arch}.zip" \
            -o /tmp/awscliv2.zip
        unzip -q /tmp/awscliv2.zip -d /tmp
        /tmp/aws/install
        rm -rf /tmp/awscliv2.zip /tmp/aws
        install_container_deps
    ;;
    *)
        echo "Unknown action, branch or build: ${CEPH_BASE_BRANCH}~${DISTRO_KIND}" >&2
        exit 2
    ;;
esac
