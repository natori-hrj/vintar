#!/usr/bin/env bash
# Rehearse a pinned candidate without network access, tags, uploads or publishing.
set -euo pipefail
umask 022

die() { printf 'Go release rehearsal: %s\n' "$*" >&2; exit 1; }
[[ $# == 3 ]] || die 'usage: rehearse_go_release.sh CANDIDATE_SHA GO_ARCHIVE NEW_OUTPUT_DIR'
commit=$1
version=v0.7.0
toolchain=go1.27.4
toolchain_sha=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
module=github.com/natori-hrj/vintar
[[ $commit =~ ^[0-9a-f]{40}$ ]] || die 'expected a full candidate SHA'
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || die 'requires a Linux amd64 rehearsal host'
archive=$(realpath -- "$2")
output_parent=$(cd -- "$(dirname -- "$3")" && pwd -P)
output="$output_parent/$(basename -- "$3")"
[[ ! -e $output && ! -L $output ]] || die 'output directory must not exist'

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
repo=$(pwd -P)
export GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1
case "$output/" in "$repo/"*) die 'output must be outside the checkout' ;; esac
check_source() {
    local index
    [[ $(git rev-parse --verify HEAD) == "$commit" &&
        -z $(git status --porcelain=v1 --untracked-files=all --ignored=matching) ]] ||
        die "requires a clean checkout of $commit"
    [[ $(git rev-parse --is-shallow-repository) == false ]] || die 'requires complete Git history'
    index=$(git ls-files -v)
    if grep -Eq '^[a-zS] ' <<<"$index"; then
        die 'masked Git index entries are not allowed'
    fi
}
check_source
if [[ ${GITHUB_ACTIONS:-} == true && ${GITHUB_SHA:-} != "$commit" ]]; then
    die 'GitHub workflow SHA must match the release candidate'
fi
read -r actual_hash _ < <(sha256sum -- "$archive")
[[ $actual_hash == "$toolchain_sha" ]] || die 'pinned Go archive checksum differs'

: "${GOMODCACHE:?set GOMODCACHE to the preseeded module cache}"
export GOMODCACHE
GOMODCACHE=$(cd -- "$GOMODCACHE" && pwd -P)
[[ -d $GOMODCACHE/cache/download ]] || die 'missing offline module proxy data'
stage=$(mktemp -d "$output_parent/.vintar-stage.XXXXXXXX")
scratch=$(mktemp -d "$output_parent/.vintar-work.XXXXXXXX")
cleanup() {
    chmod -R u+w -- "$scratch"
    rm -rf -- "$scratch" "$stage"
}
trap cleanup EXIT

mkdir -- "$scratch/go" "$stage/evidence"
tar -xzf "$archive" -C "$scratch/go" --strip-components=1
export GOROOT="$scratch/go" PATH="$scratch/go/bin:$PATH" TMPDIR="$scratch" GOTMPDIR="$scratch"
export GOENV=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0
export GOPROXY=off GOSUMDB=off GOVCS='*:off' GOAUTH=off GOINSECURE= GOFLAGS=
export GOPRIVATE= GONOPROXY= GONOSUMDB=
export GOPATH="$scratch/gopath" GOCACHE="$scratch/cache" XDG_CONFIG_HOME="$scratch/config"
unset GOCACHEPROG GOEXPERIMENT GOFIPS140 GOAMD64 GOARM64 GO_EXTLINK_ENABLED
[[ $(go env GOVERSION) == "$toolchain" && $(go env GOHOSTOS) == linux &&
    $(go env GOHOSTARCH) == amd64 ]] || die 'toolchain identity differs'
go telemetry off
printf '%s  %s.linux-amd64.tar.gz\n' "$toolchain_sha" "$toolchain" >"$stage/evidence/toolchain.sha256"

export VINTAR_VALIDATED_COMMIT="$commit"
GO_ROOT="$GOROOT" EXPECTED_GO_VERSION="$toolchain" OUT_DIR="$scratch/foundation" \
    bash scripts/check_go_foundation.sh 2>&1 | tee "$stage/evidence/foundation.log"
native="$scratch/foundation/linux-amd64/vintar"
[[ $("$native" version) == "Vintar $version" ]] || die 'native binary version differs'
cp "$scratch/foundation/targets.tsv" "$stage/evidence/"
for dir in "$scratch/foundation/"*/; do
    cp "$dir"*.buildinfo "$stage/evidence/$(basename "$dir").buildinfo"
done

# Emulate the unpublished version on an offline, per-run file proxy. The
# module ZIP comes from exactly this commit; this does not create a Git tag.
proxy="$scratch/proxy"
version_dir="$proxy/$module/@v"
mkdir -p -- "$version_dir" "$scratch/install-cwd"
git show "$commit:go.mod" >"$version_dir/$version.mod"
printf '{"Version":"%s","Time":"%s"}\n' "$version" "$(git show -s --format=%cI "$commit")" >"$version_dir/$version.info"
printf '%s\n' "$version" >"$version_dir/list"
git archive --format=zip --prefix="$module@$version/" -o "$version_dir/$version.zip" "$commit"
(
    cd -- "$scratch/install-cwd"
    GOPROXY=$(python3 -B -c 'import pathlib, sys; print(",".join(pathlib.Path(p).as_uri() for p in sys.argv[1:]))' \
        "$proxy" "$GOMODCACHE/cache/download")
    export GOPROXY
    export GOMODCACHE="$scratch/install-modules" GOBIN="$scratch/install-bin" GOCACHE="$scratch/install-cache"
    go install -trimpath "$module/cmd/vintar@$version"
    [[ $("$GOBIN/vintar" version) == "Vintar $version" ]] || die 'go install binary version differs'
    go version -m "$GOBIN/vintar" | tee "$stage/evidence/go-install.buildinfo"
    awk -F '\t' -v module="$module" -v version="$version" \
        '$2 == "mod" && $3 == module && $4 == version && $5 ~ /^h1:/ { ok = 1 } END { exit !ok }' \
        "$stage/evidence/go-install.buildinfo"
    awk 'NR == FNR { sums[$1, $2, $3] = 1; next }
         $1 == "dep" { if (!sums[$2, $3, $4]) exit 1; count++ }
         END { if (!count) exit 1 }' "$repo/go.sum" "$stage/evidence/go-install.buildinfo"
    sha256sum -- "$version_dir/$version.zip" | cut -d' ' -f1 >"$stage/evidence/go-install-source.sha256"
)

for dist in "$stage/dist" "$scratch/dist-repeat"; do
    python3 -B scripts/package_go_release.py "$scratch/foundation" "$dist" "$commit" \
        "$version" "$toolchain" "$toolchain_sha" "$repo" "$GOROOT" "$GOMODCACHE"
    (cd -- "$dist" && sha256sum --check --strict SHA256SUMS)
done
diff -r -- "$stage/dist" "$scratch/dist-repeat"
printf 'Independent packaging comparison: all distribution files identical\n' | tee "$stage/evidence/packaging.log"
check_source
mv -T -n -- "$stage" "$output"
[[ ! -e $stage ]] || die 'output directory appeared during rehearsal'
printf 'Rehearsal complete for %s (%s); files: %s\n' "$commit" "$version" "$output"
