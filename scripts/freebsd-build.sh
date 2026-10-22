#!/bin/sh
# Copy the source tree to a FreeBSD host and build it there.
# Needs Rust on the host: pkg install rust
#
#   scripts/freebsd-build.sh user@host [cargo args...]
#   scripts/freebsd-build.sh bsd test
set -eu

host=${1:?usage: $0 user@host [cargo args...]}
shift
[ $# -eq 0 ] && set -- build --release

cd "$(dirname "$0")/.."
# Non-interactive ssh skips the login profile, so find rustup's cargo, and
# fall back to the first installed toolchain when no default is set.
remote='export PATH=$HOME/.cargo/bin:$PATH
command -v rustup >/dev/null && ! rustup default >/dev/null 2>&1 &&
    export RUSTUP_TOOLCHAIN=$(rustup toolchain list | head -1 | cut -d" " -f1)
mkdir -p jmon && tar xzf - -C jmon && cd jmon && cargo'
tar czf - --exclude=./target --exclude=./.git . | ssh "$host" "$remote $*"
