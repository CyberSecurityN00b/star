#!/usr/bin/env bash

# Based on https://gist.github.com/eduncan911/68775dba9d3c028181e4

type setopt >/dev/null 2>&1

contains() {
    # Source: https://stackoverflow.com/a/8063398/7361270
    [[ $1 =~ (^|[[:space:]])$2($|[[:space:]]) ]]
}

# Setup pre-build files (to be embedded)
# - Note: These will be deleted after this script is run
openssl ecparam -genkey -name secp384r1 -out connection.key
openssl req -new -x509 -sha256 -key connection.key -out connection.crt -days 30 -nodes -subj "/C=US/CN=a" -config connection.cnf

# Delete existing binaries
rm -r ./bin

# Create binary directories
mkdir ./bin
mkdir ./bin/agents
mkdir ./bin/terminals

# Post-build function
post_build () {
    echo "--- Performing post-build actions on $1"
    upx -9 $1
}

# Build agents for all targets
FAILURES=""
REMOVEDS=""

echo "Building all agents..."

while IFS= read -r target; do
    GOOS=${target%/*}
    GOARCH=${target#*/}
    BIN_FILENAME="./bin/agents/star-agent-${GOOS}-${GOARCH}"
    if [[ "${GOOS}" == "windows" ]]; then BIN_FILENAME="${BIN_FILENAME}.exe"; fi
    CMD="GOOS=${GOOS} GOARCH=${GOARCH} go build -ldflags \"-s -w\" -o ${BIN_FILENAME} ./agent.go"
    echo "--- Building ${BIN_FILENAME}"
    eval "${CMD}" || FAILURES="${FAILURES} agent:${GOOS}/${GOARCH}"
    post_build "${BIN_FILENAME}"
    echo ""
done <<< "$(go tool dist list)"

# No point in that wasm...
rm ./bin/agents/star-agent-js-wasm
REMOVEDS="${REMOVEDS} agent:js/wasm"

# Build terminal locally
echo "Building local terminals..."

go build -ldflags "-s -w" -o ./bin/star_terminal ./terminal.go
post_build "./bin/star_terminal" 

# Build terminals for all targets
echo "Building all terminals..."

while IFS= read -r target; do
    GOOS=${target%/*}
    GOARCH=${target#*/}
    BIN_FILENAME="./bin/terminals/star-terminal-${GOOS}-${GOARCH}"
    if [[ "${GOOS}" == "windows" ]]; then BIN_FILENAME="${BIN_FILENAME}.exe"; fi
    CMD="GOOS=${GOOS} GOARCH=${GOARCH} go build -ldflags \"-s -w\" -o ${BIN_FILENAME} ./terminal.go"
    echo "--- Building ${BIN_FILENAME}"
    eval "${CMD}" || FAILURES="${FAILURES} terminal:${GOOS}/${GOARCH}"
    post_build "${BIN_FILENAME}"
    echo ""
done <<< "$(go tool dist list)"

# No point in that wasm...
rm ./bin/terminals/star-terminal-js-wasm
REMOVEDS="${REMOVEDS} terminal:js/wasm"

# Cleanup pre-build files
#rm -f connection.crt
#rm -f connection.key

if [[ "${FAILURES}" != "" ]]; then
    echo ""
    echo "STAR build failed on: ${FAILURES}"
    echo "STAR builds deleted : ${REMOVEDS}"
    exit 1
fi

