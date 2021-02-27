#!/usr/bin/env bash

# Based on https://gist.github.com/eduncan911/68775dba9d3c028181e4

type setopt >/dev/null 2>&1

contains() {
    # Source: https://stackoverflow.com/a/8063398/7361270
    [[ $1 =~ (^|[[:space:]])$2($|[[:space:]]) ]]
}

# Todo: Setup pre-build files (to be embedded)

# Delete existing binaries
rm -r ./bin

# Build agents for all targets
FAILURES=""

echo "Building agents..."

while IFS= read -r target; do
    GOOS=${target%/*}
    GOARCH=${target#*/}
    BIN_FILENAME="./bin/agents/star-agent-${GOOS}-${GOARCH}"
    if [[ "${GOOS}" == "windows" ]]; then BIN_FILENAME="${BIN_FILENAME}.exe"; fi
    CMD="GOOS=${GOOS} GOARCH=${GOARCH} go build -ldflags \"-s -w\" -o ${BIN_FILENAME} ./agent.go"
    echo "${CMD}"
    eval "${CMD}" || FAILURES="${FAILURES} agent:${GOOS}/${GOARCH}"
    upx -9 ${BIN_FILENAME}
done <<< "$(go tool dist list)"

# Build terminal locally
echo "Building local terminal..."

go build -ldflags "-s -w" -o ./bin/star-terminal ./terminal.go

# Build terminals for all targets
echo "Building terminals..."

while IFS= read -r target; do
    GOOS=${target%/*}
    GOARCH=${target#*/}
    BIN_FILENAME="./bin/terminals/star-terminal-${GOOS}-${GOARCH}"
    if [[ "${GOOS}" == "windows" ]]; then BIN_FILENAME="${BIN_FILENAME}.exe"; fi
    CMD="GOOS=${GOOS} GOARCH=${GOARCH} go build -ldflags \"-s -w\" -o ${BIN_FILENAME} ./terminal.go"
    echo "${CMD}"
    eval "${CMD}" || FAILURES="${FAILURES} terminal:${GOOS}/${GOARCH}"
    upx -9 ${BIN_FILENAME}
done <<< "$(go tool dist list)"

if [[ "${FAILURES}" != "" ]]; then
    echo ""
    echo "STAR build failed on: ${FAILURES}"
    exit 1
fi