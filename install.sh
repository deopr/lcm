#!/bin/sh
# Install lcm from a source checkout into /usr/local.
#
# Usage:
#   sudo ./install.sh
#
# Works on Debian/Ubuntu, Fedora and Arch.  It installs the distribution's
# PyYAML package when Python cannot import yaml, then copies the source tree
# and writes a small launcher.  No network access beyond the package manager.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prefix=${PREFIX:-/usr/local}
libdir="$prefix/lib/lcm"

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: run as root (sudo ./install.sh)" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "install.sh: python3 is required" >&2
    exit 1
fi

install_yaml() {
    if python3 -c "import yaml" >/dev/null 2>&1; then
        return 0
    fi
    echo "install.sh: installing PyYAML"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y python3-yaml
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3-pyyaml
    elif command -v pacman >/dev/null 2>&1; then
        pacman -S --needed --noconfirm python-yaml
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install python3-PyYAML
    else
        echo "install.sh: cannot install PyYAML automatically" >&2
        echo "install PyYAML for python3 and re-run" >&2
        exit 1
    fi
    python3 -c "import yaml" >/dev/null 2>&1 || {
        echo "install.sh: PyYAML still not importable" >&2
        exit 1
    }
}

install_yaml

echo "install.sh: copying to $libdir"
rm -rf "$libdir"
install -d "$libdir"
cp -a "$here/src" "$libdir/src"

cat >"$prefix/bin/lcm" <<LAUNCHER
#!/bin/sh
PYTHONPATH="$libdir/src\${PYTHONPATH:+:\$PYTHONPATH}"
export PYTHONPATH
exec python3 -m lcm "\$@"
LAUNCHER
chmod 0755 "$prefix/bin/lcm"

echo "install.sh: installed $("$prefix/bin/lcm" --version)"
echo "Try: sudo lcm check --target debian"
