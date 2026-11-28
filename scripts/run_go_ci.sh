#!/usr/bin/env bash
# Run with Bash from a clean Linux amd64 checkout. Evidence stays on this host.
# Local runs may set VINTAR_GO_ARCHIVE_DIR to preseed either official Go archive.
set -euo pipefail
umask 077

die() { printf 'Go CI: %s\n' "$*" >&2; exit 1; }

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
repo=$(pwd -P)
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || die 'requires Linux amd64'
export GIT_OPTIONAL_LOCKS=0 GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1
commit=$(git rev-parse --verify HEAD)
[[ $commit =~ ^[0-9a-f]{40}$ ]] || die 'expected a Git SHA-1 commit'
if [[ ${GITHUB_ACTIONS:-} == true || -v GITHUB_SHA ]]; then
    [[ ${GITHUB_SHA:-} == "$commit" ]] || die 'checkout HEAD does not match GITHUB_SHA'
fi

check_checkout() {
    local head status paths entry
    head=$(git rev-parse --verify HEAD)
    status=$(git -c core.fsmonitor=false -c core.untrackedCache=false status \
        --porcelain=v1 --untracked-files=all --ignored=matching --ignore-submodules=none)
    [[ $head == "$commit" && -z $status ]] ||
        die "requires a clean checkout of $commit (including ignored files)"
    paths=$(git -c core.fsmonitor=false ls-files -v)
    while IFS= read -r entry; do
        case "$entry" in
            [a-z]' '* | 'S '*) die 'assume-unchanged and skip-worktree entries are not allowed' ;;
        esac
    done <<<"$paths"
}
check_checkout
[[ $(git rev-parse --is-shallow-repository) == false ]] || die 'requires complete Git history'

temp_parent=$(cd -- "${RUNNER_TEMP:-${TMPDIR:-/tmp}}" && pwd -P)
case "$temp_parent/" in "$repo/"*) die 'temporary directory must be outside the checkout' ;; esac
export TMPDIR="$temp_parent"
results=$(mktemp -d "$temp_parent/vintar-go-ci.XXXXXXXX")
scratch="$results/work"
phase='initialization'
versions=(go1.26.0 go1.27.4)
archive_hashes=(
    aac1b08a0fb0c4e0a7c1555beb7b59180b05dfc5a3d62e40e9de90cd42f88235
    7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
)
govuln_module=golang.org/x/vuln
govuln_version=v1.10.0

finish() {
    local status=$? version rev tool target digest match
    trap - EXIT
    {
        printf '## Vintar Go CI\n\nCommit: `%s` · Host: `linux/amd64`\n\n' "$commit"
        if ((status == 0)); then
            printf '**Passed** · Gitleaks history scan and govulncheck `%s` passed.\n\n' "$govuln_version"
        else
            printf '**Failed** during %s (exit %s). Rows below are completed byte comparisons, not an overall pass.\n\n' \
                "$phase" "$status"
        fi
        printf '| Go | Target | SHA-256 | Independent rebuild |\n| --- | --- | --- | --- |\n'
        for version in "${versions[@]}"; do
            [[ -f $results/$version/targets.tsv ]] || continue
            while IFS=$'\t' read -r rev tool target digest match; do
                [[ $rev == "$commit" && $tool == "$version" ]] || continue
                printf '| `%s` | `%s` | `%s` | %s |\n' "$tool" "$target" "$digest" "$match"
            done <"$results/$version/targets.tsv"
        done
        printf '\nNative artifact acceptance (`linux/amd64` only):'
        for version in "${versions[@]}"; do
            if [[ -f $results/$version/foundation.ok ]]; then
                printf ' `%s` passed;' "$version"
            else
                printf ' `%s` not confirmed;' "$version"
            fi
        done
        printf ' all other targets are build-only.\n'
    } >"$results/summary.md"
    cat -- "$results/summary.md"
    if [[ ${GITHUB_ACTIONS:-} == true && -n ${GITHUB_STEP_SUMMARY:-} ]]; then
        cat -- "$results/summary.md" >>"$GITHUB_STEP_SUMMARY"
    fi
    rm -rf -- "$scratch"
    printf 'Local Go CI evidence: %s\n' "$results"
    exit "$status"
}
trap finish EXIT
printf 'Validating commit %s; evidence: %s\n' "$commit" "$results"

mkdir -p -- "$scratch"
# No user Go configuration, automatic toolchain downloads, private module
# exceptions, external build cache, or telemetry uploads.
export GOENV=off GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOVCS='*:off'
export GOPRIVATE= GONOPROXY= GONOSUMDB= GOINSECURE= GOFLAGS= GOAUTH=off
unset GOCACHEPROG GOEXPERIMENT GOFIPS140 GOAMD64 GOARM64 GO_EXTLINK_ENABLED
export XDG_CONFIG_HOME="$scratch/config"
export VINTAR_VALIDATED_COMMIT="$commit"

install_go() {
    local version=$1 hash=$2 dest=$3 archive filename
    filename="$version.linux-amd64.tar.gz"
    archive="$scratch/$filename"
    if [[ ${GITHUB_ACTIONS:-} != true && -n ${VINTAR_GO_ARCHIVE_DIR:-} &&
        -f $VINTAR_GO_ARCHIVE_DIR/$filename ]]; then
        cp -- "$VINTAR_GO_ARCHIVE_DIR/$filename" "$archive"
    else
        curl --disable --fail --silent --show-error --location \
            --proto '=https' --proto-redir '=https' --retry 3 --max-time 300 \
            --output "$archive" "https://go.dev/dl/$filename"
    fi
    (cd -- "$scratch" && printf '%s  %s\n' "$hash" "$filename" | sha256sum --check --strict -)
    mkdir -p -- "$dest"
    tar -xzf "$archive" -C "$dest" --strip-components=1
    rm -- "$archive"
}

phase='Gitleaks history scan'
# The existing helper verifies the pinned archive even when cached locally.
if [[ ${GITHUB_ACTIONS:-} == true ]]; then
    XDG_CACHE_HOME="$scratch/gitleaks-cache" python3 scripts/scan_git_history.py \
        2>&1 | tee "$results/gitleaks.log"
else
    python3 scripts/scan_git_history.py 2>&1 | tee "$results/gitleaks.log"
fi

for i in "${!versions[@]}"; do
    version=${versions[i]}
    phase="$version toolchain verification"
    root="$scratch/$version"
    install_go "$version" "${archive_hashes[i]}" "$root"
    (
        export GOROOT="$root"
        export PATH="$root/bin:$PATH"
        [[ $("$root/bin/go" env GOVERSION) == "$version" ]] || die "expected $version"
        [[ $("$root/bin/go" env GOHOSTOS) == linux && $("$root/bin/go" env GOHOSTARCH) == amd64 ]] ||
            die 'unexpected Go toolchain host'
        "$root/bin/go" telemetry off
    )
    phase="$version foundation gate"
    mkdir -- "$results/$version"
    printf '%s  %s.linux-amd64.tar.gz\n' "${archive_hashes[i]}" "$version" \
        >"$results/$version/toolchain.sha256"
    GO_ROOT="$root" EXPECTED_GO_VERSION="$version" OUT_DIR="$results/$version" \
        GOPATH="$scratch/$version-gopath" GOMODCACHE="$scratch/product-modules" \
        GOCACHE="$scratch/$version-check-cache" \
        bash scripts/check_go_foundation.sh 2>&1 | tee "$results/$version/foundation.log"
    touch -- "$results/$version/foundation.ok"
done

phase="govulncheck $govuln_version installation or scan"
(
    export GOROOT="$scratch/go1.27.4"
    export PATH="$GOROOT/bin:$PATH"
    export GOPATH="$scratch/vuln-gopath" GOMODCACHE="$scratch/vuln-modules"
    export GOCACHE="$scratch/vuln-cache" GOBIN="$scratch/vuln-bin"
    export GOOS=linux GOARCH=amd64
    # A fresh module cache and the public checksum database authenticate this
    # versioned install; do not use a scanner from PATH or the product module.
    "$GOROOT/bin/go" install "$govuln_module/cmd/govulncheck@$govuln_version"
    (cd -- "$GOBIN" && "$GOROOT/bin/go" version -m govulncheck) |
        tee "$results/govulncheck.buildinfo"
    grep -Fxq 'govulncheck: go1.27.4' "$results/govulncheck.buildinfo"
    grep -Fxq $'\tpath\t'"$govuln_module/cmd/govulncheck" "$results/govulncheck.buildinfo"
    awk -F '\t' -v mod="$govuln_module" -v version="$govuln_version" \
        '$2 == "mod" && $3 == mod && $4 == version && $5 ~ /^h1:.+$/ { found = 1 }
         END { exit !found }' "$results/govulncheck.buildinfo"
    export GOFLAGS=-mod=readonly GOMODCACHE="$scratch/product-modules"
    "$GOBIN/govulncheck" -db https://vuln.go.dev ./...
) 2>&1 | tee "$results/govulncheck.log"

phase='final checkout verification'
check_checkout
