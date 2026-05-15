# Intentionally vulnerable Ubuntu image for exercising patchmgr.
#
# Pinned to a focal point release that is known to ship with stale
# `openssl`, `libc6`, `openssh-server` etc. No `apt-get upgrade` is
# run, so the package manager will report many security updates and
# the NVD lookup will surface real CVEs.
#
# !! NEVER expose this container to a network you do not control. !!

FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    TZ=Etc/UTC

# ---------------------------------------------------------------------------
# Base SSH server + sudo. We intentionally avoid `apt-get upgrade` so the
# image keeps the stale package versions baked into the base layer — that
# is the whole point of this image.
# ---------------------------------------------------------------------------
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        openssh-server \
        sudo \
        ca-certificates \
        curl \
        iproute2 \
        less \
 && mkdir -p /var/run/sshd
# NOTE: we deliberately keep /var/lib/apt/lists/* in the image so that
# `apt-get -s upgrade` inside the running container has a fresh package
# index to compare against. Without it, patchmgr would always report
# "0 missing patches" because apt has no candidate versions to suggest.

# ---------------------------------------------------------------------------
# Local 'patchadmin' user.
# - password = patchadmin (also accepts an SSH key mounted at runtime)
# - passwordless sudo for the package managers + shutdown
# ---------------------------------------------------------------------------
RUN useradd -m -s /bin/bash patchadmin \
 && echo 'patchadmin:patchadmin' | chpasswd \
 && printf 'patchadmin ALL=(ALL) NOPASSWD: /usr/bin/apt-get, /usr/bin/dpkg, /sbin/shutdown, /usr/sbin/shutdown, /usr/bin/dpkg-query\n' \
        > /etc/sudoers.d/patchadmin \
 && chmod 0440 /etc/sudoers.d/patchadmin

# ---------------------------------------------------------------------------
# sshd configuration: allow password auth (for the simple demo) and disable
# root login. PubkeyAuthentication remains on so users can mount a key.
# ---------------------------------------------------------------------------
# Test-only: set a root password and allow root over SSH so the patchmgr
# CLI can run apt-get without going through sudoers. Real hosts must
# keep PermitRootLogin = no — this container is bound to 127.0.0.1 in
# docker-compose.yml so it is not network-reachable from outside.
RUN echo 'root:root' | chpasswd

RUN sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config \
 && sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config

# Generate fresh host keys at build time so each image rebuild has a
# unique fingerprint. Operators must trust the key on first connection
# (or run patchmgr with `ssh_strict_host_key_checking: false`).
RUN ssh-keygen -A

# ---------------------------------------------------------------------------
# Optional: copy a pre-generated public key into authorized_keys if one is
# provided in the build context. This lets advanced users skip password
# auth without rebuilding the image.
# ---------------------------------------------------------------------------
COPY --chown=patchadmin:patchadmin authorized_keys* /home/patchadmin/.ssh/
RUN if [ -f /home/patchadmin/.ssh/authorized_keys ]; then \
        chmod 700 /home/patchadmin/.ssh && \
        chmod 600 /home/patchadmin/.ssh/authorized_keys ; \
    fi

EXPOSE 22

# `-e` sends sshd logs to stderr so `docker logs` captures them.
CMD ["/usr/sbin/sshd", "-D", "-e"]
