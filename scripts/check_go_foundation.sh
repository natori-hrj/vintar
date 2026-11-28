#!/usr/bin/env bash
# Run with Bash. GO_ROOT may point to a verified Go distribution; default to PATH.
# For a separate, optional race run on a supported host with a C toolchain:
# GOTOOLCHAIN=local CGO_ENABLED=1 go test -count=1 -race ./...
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ -n ${GO_ROOT:-} ]]; then
    export PATH="$GO_ROOT/bin:$PATH"
    export GOROOT="$GO_ROOT"
fi
export GOTOOLCHAIN=local CGO_ENABLED=0 GOWORK=off GOFLAGS=-mod=readonly
unset VINTAR_TEST_BINARY

expected=${EXPECTED_GO_VERSION:-go1.26.0}
actual=$(go env GOVERSION)
if [[ $actual != "$expected" ]]; then
    printf 'Go version mismatch: expected %s, got %s (GOTOOLCHAIN=local)\n' "$expected" "$actual" >&2
    exit 1
fi
printf 'Go foundation gate: %s, CGO disabled\n' "$actual"
test "$(go env CGO_ENABLED)" = 0
grep -Fxq 'go 1.26.0' go.mod
GOOS=$(go env GOHOSTOS)
GOARCH=$(go env GOHOSTARCH)
export GOOS GOARCH

scratch=$(mktemp -d "${TMPDIR:-/tmp}/vintar-go-foundation.XXXXXXXX")
trap 'rm -rf -- "$scratch"' EXIT
out=${OUT_DIR:-"$scratch/artifacts"}
mkdir -p -- "$out"
out=$(cd -- "$out" && pwd -P)

find . -name .git -prune -o -type f -name '*.go' -print0 >"$scratch/go-files"
sources=()
while IFS= read -r -d '' file; do
    sources+=("$file")
done <"$scratch/go-files"
if ((${#sources[@]} == 0)); then
    printf 'No Go source files found\n' >&2
    exit 1
fi
unformatted=$(gofmt -l "${sources[@]}")
if [[ -n $unformatted ]]; then
    printf 'Run gofmt on:\n%s\n' "$unformatted" >&2
    exit 1
fi
go mod verify
go test -count=1 ./...
go vet ./...

checksum() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1"
    else
        printf 'Need sha256sum or shasum\n' >&2
        return 1
    fi
}

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
    os=${target%/*}
    arch=${target#*/}
    exe=vintar
    if [[ $os == windows ]]; then
        exe=vintar.exe
    fi
    dir="$out/$os-$arch"
    mkdir -p -- "$dir"
    binary="$dir/$exe"
    printf 'Build %s (CGO_ENABLED=0)\n' "$target"
    GOOS="$os" GOARCH="$arch" go build -trimpath -o "$binary" ./cmd/vintar
    metadata=$(go version -m "$binary")
    printf '%s\n' "$metadata"
    printf '%s\n' "$metadata" >"$binary.buildinfo"
    [[ ${metadata%%$'\n'*} == *": $actual" ]]
    grep -Fxq $'\tpath\tgithub.com/natori-hrj/vintar/cmd/vintar' <<<"$metadata"
    grep -Fxq $'\tbuild\tCGO_ENABLED=0' <<<"$metadata"
    grep -Fxq $'\tbuild\tGOOS='"$os" <<<"$metadata"
    grep -Fxq $'\tbuild\tGOARCH='"$arch" <<<"$metadata"
    if grep -Fq 'github.com/santhosh-tekuri/jsonschema/v6' <<<"$metadata"; then
        printf 'Test-only JSON Schema module is linked into %s\n' "$target" >&2
        exit 1
    fi
    (cd -- "$dir" && checksum "$exe" >"$exe.sha256")
done

# Cross-builds and matching metadata are not evidence of runtime conformance.
# Only run a built artifact when both the observed runner and Go host match.
host_os=
host_arch=
case "$(uname -s)" in
    Linux) host_os=linux ;;
    Darwin) host_os=darwin ;;
    MINGW* | MSYS* | CYGWIN*) host_os=windows ;;
esac
case "$(uname -m)" in
    x86_64 | amd64) host_arch=amd64 ;;
    aarch64 | arm64) host_arch=arm64 ;;
esac

native=$host_os/$host_arch
case "$native" in
    linux/amd64 | linux/arm64 | darwin/amd64 | darwin/arm64 | windows/amd64)
        if [[ $native != "$GOOS/$GOARCH" ]]; then
            printf 'Native artifact gate not run: runner %s, Go host %s/%s\n' "$native" "$GOOS" "$GOARCH"
            exit 0
        fi
        exe=vintar
        if [[ $host_os == windows ]]; then
            exe=vintar.exe
        fi
        dir="$out/$host_os-$host_arch"
        (cd -- "$dir" && test "$(checksum "$exe")" = "$(cat "$exe.sha256")")
        binary="$dir/$exe"
        if [[ $host_os == windows ]]; then
            binary=$(cygpath -am "$binary")
        fi
        printf 'Native artifact gate for %s only: %s\n' "$native" "$binary"
        VINTAR_TEST_BINARY="$binary" go test -count=1 -v ./internal/acceptance -run '^TestProductBinary$'
        ;;
    *)
        printf 'Native artifact gate not run: unsupported runner (%s, %s)\n' "$(uname -s)" "$(uname -m)"
        ;;
esac
