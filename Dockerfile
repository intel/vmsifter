# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

ARG BASEIMAGE=pypy:3.11-7-slim-bookworm
ARG BUILD_ID=""
FROM ${BASEIMAGE} AS vmsifter-deps
LABEL build=${BUILD_ID}

ENV DEBIAN_FRONTEND=noninteractive

# update cache and install essential tools
RUN --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
  --mount=type=cache,target=/var/cache/apt,sharing=locked <<EOF
set -e
apt-get update
apt-get -y upgrade
apt-get install -y --no-install-recommends \
  git build-essential meson ninja-build \
  python3 python3-dev python3-setuptools \
  iasl uuid-dev libncurses-dev \
  pkg-config libglib2.0-dev libpixman-1-dev \
  libyajl-dev flex bison ninja-build curl cmake libjson-c-dev \
  rsync python3-pip sudo ccache dmidecode libgcc-11-dev
apt-get clean
rm -rf /var/lib/apt/lists/*
EOF

FROM vmsifter-deps AS vmsifter-xtf-builder
LABEL build=${BUILD_ID}

COPY ./xtf/ /code/xtf/
COPY ./patches/ /code/patches/

WORKDIR /code/xtf

ENV DESTDIR="/code/xtf-install"

RUN <<EOF
set -e
patch -p1 < ../patches/0001-xtf-VMSifter-test-execution-VM.patch
make TESTS=tests/vmsifter -e -j "$(nproc)"
make TESTS=tests/vmsifter install
EOF

FROM vmsifter-deps AS vmsifter-xen-builder
LABEL build=${BUILD_ID}
ENV CCACHE_DIR=/root/.ccache
ENV PATH=/usr/lib/ccache:$PATH

COPY ./xen /code/xen/
COPY ./patches/ /code/patches/

ENV DESTDIR="/code/xen-install"

WORKDIR /code/xen

RUN --mount=type=cache,target=/root/.ccache <<EOF
set -e
make distclean
patch -p1 < ../patches/0001-xen-x86-Make-XEN_DOMCTL_get_vcpu_msrs-more-configura.patch
patch -p1 < ../patches/0003-xen-x86-monitor-report-extra-vmexit-information.patch
./configure --disable-xen --disable-docs  --disable-stubdom --disable-pvshim --enable-githttp
# https://bugzilla.redhat.com/show_bug.cgi?id=2217084
# append "-Wno-declaration-after-statement" flag to python and pygrub Makefile CFLAGS
sed -i '/^PY_CFLAGS\s*=/ s/$/ -Wno-declaration-after-statement/' tools/python/Makefile tools/pygrub/Makefile
make -e -j "$(nproc)" dist-tools
make -e install-tools
EOF

FROM vmsifter-deps AS vmsifter-libvmi-builder
LABEL build=${BUILD_ID}

COPY ./libvmi /code/libvmi
COPY ./patches/ /code/patches/
COPY --from=vmsifter-xen-builder /code/xen-install /code/xen-install

WORKDIR /code/libvmi

RUN <<EOF
set -e
patch -p1 < /code/patches/0001-libvmi-vmexit-instruction-infos.patch
mkdir -p /code/libvmi/build/
rsync -au /code/xen-install/ /
cmake -DCMAKE_INSTALL_PREFIX=/code/libvmi-install \
  -DXenstore_INCLUDE_DIR=/usr/local/include/ \
  -DXen_INCLUDE_DIR=/usr/local/include/ \
  -B /code/libvmi/build/ -S /code/libvmi/
cmake --build /code/libvmi/build --parallel "$(nproc)"
cmake --install /code/libvmi/build
EOF


FROM vmsifter-deps AS vmsifter-injector-builder
LABEL build=${BUILD_ID}

COPY --from=vmsifter-xtf-builder /code/xtf-install/code/xtf/  /code/xtf/
COPY --from=vmsifter-xen-builder /code/xen-install/ /code/xen-install/
COPY --from=vmsifter-libvmi-builder /code/libvmi-install/ /code/libvmi-install/
RUN <<EOF
set -e
rsync -au /code/xen-install/ /
rsync -au /code/libvmi-install/ /usr/local/
EOF

# setup injector
COPY ./src/ /code/src/
COPY ./meson.build /code/meson.build
WORKDIR /code
RUN <<EOF
meson setup build
ninja -C build install
EOF

FROM ${BASEIMAGE} AS python-base
ARG POETRY_VERSION="2.1.1"

COPY --from=vmsifter-xtf-builder /code/xtf-install/code/xtf/  /code/xtf/
COPY --from=vmsifter-xen-builder /code/xen-install/ /code/xen-install/
COPY --from=vmsifter-libvmi-builder /code/libvmi-install/ /code/libvmi-install/
COPY --from=vmsifter-injector-builder /usr/local/bin/injector /usr/local/bin/injector

RUN <<EOF
set -e
apt-get update && apt-get install --no-install-recommends -y \
  build-essential rsync curl sudo dmidecode libyajl-dev \
  libjson-c-dev libglib2.0-dev libpixman-1-dev
rsync -au /code/xen-install/ /
rsync -au /code/libvmi-install/ /usr/local/
# cleanup
apt-get upgrade -y
apt-get clean
rm -rf /var/lib/apt/lists/*
EOF

# ensure xl is setuid
RUN chmod u+s /usr/local/sbin/xl

# setup python env vars
ENV PYTHONUNBUFFERED=1 \
    # pip
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    \
    # Poetry
    # https://python-poetry.org/docs/configuration/#using-environment-variables
    POETRY_VERSION=${POETRY_VERSION} \
    # make poetry install to this location
    POETRY_HOME="/opt/poetry" \
    # do not ask any interactive question
    POETRY_NO_INTERACTION=1 \
    # never create virtual environment automaticly, only use env prepared by us
    POETRY_VIRTUALENVS_CREATE=false \
    \
    # this is where our requirements + virtual environment will live
    VIRTUAL_ENV="/venv"

# prepend poetry and venv to path
ENV PATH="$POETRY_HOME/bin:$VIRTUAL_ENV/bin:$PATH"

# prepare virtual env
RUN python -m venv $VIRTUAL_ENV

WORKDIR /code/
ENV PYTHONPATH="/code:$PYTHONPATH"

# install poetry - respects $POETRY_VERSION & $POETRY_HOME
# The --mount will mount the buildx cache directory to where
# Poetry and Pip store their cache so that they can re-use it
RUN --mount=type=cache,target=/root/.cache,sharing=locked \
    curl -sSL https://install.python-poetry.org | python -

COPY ./poetry.lock ./pyproject.toml ./
# install runtime deps
RUN --mount=type=cache,target=/root/.cache,sharing=locked \
  poetry install --only=main --no-root
COPY ./vmsifter ./vmsifter
# install app
RUN --mount=type=cache,target=/root/.cache,sharing=locked \
  poetry install --only-root

RUN <<EOF
set -e
echo "%sudo	ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers.d/sudogrp
# create group for developers
groupadd dev
# create first 500 users (avoid "I have no name" and "sudo: you do not exist in the passwd database")
for i in $(seq 50); do
    useradd --create-home "runner${i}" --groups dev
    # create "$HOME/.sudo_as_admin_successful" to prevent annoying message from Ubuntu /etc/bash.bashrc
    # https://askubuntu.com/questions/813942/is-it-possible-to-stop-sudo-as-admin-successful-being-created
    touch "/home/runner${i}/.sudo_as_admin_successful"
done
EOF

RUN mkdir /workdir && chmod o+w /workdir
VOLUME ["/workdir"]

# override xtf path since it has been copied in /code
ENV VMSIFTER_INJECTOR.XENVM.XTF_PATH=/code/xtf
ENV VMSIFTER_WORKDIR=/workdir
RUN ldconfig && mkdir -p /var/run/xen
# ignore docopt SyntaxWarning
# TODO: reduce scope to docopt
ENV PYTHONWARNINGS="ignore"

FROM python-base AS vmsifter-dev

# ensure permissions for all users
RUN chown -R root:dev /code

ENTRYPOINT [ "poetry", "run", "vmsifter" ]

FROM python-base AS vmsifter-prod

RUN <<EOF
set -e
poetry build -f wheel
python3 -m pip install --no-cache-dir dist/*.whl
python3 -m pip install --no-cache-dir pdbpp==0.10.3
EOF

ENTRYPOINT ["vmsifter"]
