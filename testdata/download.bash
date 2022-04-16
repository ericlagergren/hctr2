#!/usr/bin/env bash

set -xeuo pipefail

base="https://raw.githubusercontent.com/google/hctr2/main/test_vectors/ours"
download() {
	name="${1}_AES${2}.json"
	curl "${base}/${1}/${name}" >"${name}"
}

sizes=(128 192 256)
algs=(XCTR HCTR2)
for alg in "${algs[@]}"; do
	for size in "${sizes[@]}"; do
		download "${alg}" "${size}"
	done
done
