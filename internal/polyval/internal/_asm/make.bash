#!/usr/bin/env bash

set -xeuo pipefail

mkdir -p out
go run asm.go \
	-out out/polyval_amd64.s \
	-stubs out/stub_amd64.go \
	-pkg polyval
gofmt -s -w out/*.go
asmfmt -w out/*.s
mv out/* ../../
rmdir out
