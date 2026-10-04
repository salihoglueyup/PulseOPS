#!/bin/sh
# Turns a bare distro container into a small "real server" for tests/test_distros.py:
# ss/ps/sudo installed, sshd listening on :22, a `deploy` user with passwordless sudo.
set -eu

if command -v apk >/dev/null; then
    apk add -q openssh iproute2 procps-ng sudo shadow
elif command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q >/dev/null
    apt-get install -y -q --no-install-recommends iproute2 procps openssh-server sudo >/dev/null
elif command -v dnf >/dev/null; then
    dnf install -y -q iproute procps-ng openssh-server sudo shadow-utils >/dev/null
else
    echo "unsupported distro" >&2
    exit 1
fi

ssh-keygen -A >/dev/null
mkdir -p /run/sshd
/usr/sbin/sshd
useradd -m -s /bin/sh deploy
mkdir -p /etc/sudoers.d
echo 'deploy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/deploy
chmod 0440 /etc/sudoers.d/deploy
