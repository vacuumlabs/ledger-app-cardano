#!/bin/bash -eu

export BOLOS_SDK=/ledger-secure-sdk

# build fuzzers using the docker images.
pushd tests/fuzzing
cmake -S . -B build -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug \
            -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=On \
            -DBOLOS_SDK="${BOLOS_SDK}" -DTARGET=flex \
            -DAPP_BUILD_PATH=/app

# Generates <fuzzer>_seed_corpus.zip for the initial corpus in ClusterFuzz/OSS-Fuzz.
# Seed dirs live under seeds/<fuzzer>/ (see generate_seed_corpus.py).
for dir in seeds/*; do
    if [ -d "${dir}" ]; then
        fuzzer_name=$(basename "${dir}")
        zip_name="${fuzzer_name}_seed_corpus.zip"
        echo "Zipping corpus from ${dir} into ${zip_name}"

        (cd "${dir}" && zip -q -r "${zip_name}" .)

        mv "${dir}/${zip_name}" "${OUT}"
    fi
done
cmake --build build
mv ./build/fuzz_* "${OUT}"

# Auto-load the shared dictionary: OSS-Fuzz/ClusterFuzzLite loads <fuzzer>.dict next to each binary.
if [ -f dict/cardano.dict ]; then
    for fuzzer in "${OUT}"/fuzz_*; do
        case "${fuzzer}" in *.zip | *.dict) continue ;; esac
        cp dict/cardano.dict "${fuzzer}.dict"
    done
fi
popd
