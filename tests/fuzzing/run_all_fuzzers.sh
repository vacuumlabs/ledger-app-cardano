#!/usr/bin/env bash
set -euo pipefail

umask 077

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <timeout_seconds> [output_dir]"
  echo "Example: $0 600 out-local"
  exit 1
fi

timeout_seconds="$1"
output_dir="${2:-out-local}"

if ! [[ "$timeout_seconds" =~ ^[0-9]+$ ]] || [[ "$timeout_seconds" -le 0 ]]; then
  echo "Error: timeout_seconds must be a positive integer"
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build_dir="$script_dir/build"

# Shared libFuzzer dictionary (APDU/CBOR/Cardano tokens). Passed only if present,
# so the script still works if it is absent.
dict_file="$script_dir/dict/cardano.dict"
dict_arg=()
if [[ -f "$dict_file" ]]; then
  dict_arg=(-dict="$dict_file")
fi

if [[ "$output_dir" = /* ]]; then
  output_root="$output_dir"
else
  output_root="$script_dir/$output_dir"
fi

if [[ ! -d "$build_dir" ]]; then
  echo "Error: build directory not found: $build_dir"
  echo "Build first, e.g.:"
  echo "  cmake -S tests/fuzzing -B tests/fuzzing/build -DBOLOS_SDK=/opt/ledger-secure-sdk -DTARGET=stax"
  echo "  cmake --build tests/fuzzing/build -j4"
  exit 1
fi

shopt -s nullglob
fuzzers=("$build_dir"/fuzz_*)
shopt -u nullglob

if [[ ${#fuzzers[@]} -eq 0 ]]; then
  echo "Error: no fuzzers found in $build_dir (expected fuzz_*)"
  exit 1
fi

# Try requested output location first, then fallback to /tmp if not writable.
if ! mkdir -p "$output_root/logs" "$output_root/artifacts" "$output_root/corpus" 2>/dev/null; then
  fallback_root="$(mktemp -d "${TMPDIR:-/tmp}/cardano-fuzz-out.XXXXXX")"
  echo "Warning: cannot write to '$output_root', falling back to '$fallback_root'"
  output_root="$fallback_root"
  mkdir -p "$output_root/logs" "$output_root/artifacts" "$output_root/corpus"
fi

echo "Running ${#fuzzers[@]} harnesses for ${timeout_seconds}s each"
echo "Output directory: $output_root"

# libFuzzer + LeakSanitizer can report teardown-only failures in some environments,
# producing misleading crash artifacts (often for empty input).
# Keep this overridable: if ASAN_OPTIONS already sets detect_leaks, respect it.
asan_options="${ASAN_OPTIONS:-}"
if [[ -z "$asan_options" ]]; then
  asan_options="detect_leaks=0"
elif [[ "$asan_options" != *detect_leaks=* ]]; then
  asan_options="detect_leaks=0:$asan_options"
fi

failure_count=0

for fuzzer in "${fuzzers[@]}"; do
  name="$(basename "$fuzzer")"
  corpus_dir="$output_root/corpus/$name"
  artifact_dir="$output_root/artifacts/$name"
  log_file="$output_root/logs/$name.log"

  mkdir -p "$corpus_dir" "$artifact_dir"

  # Committed seed corpus (valid APDU sequences from the test suite), if present for
  # this harness. Passed as an extra read-only corpus dir that libFuzzer merges in.
  seed_arg=()
  if [[ -d "$script_dir/seeds/$name" ]]; then
    seed_arg=("$script_dir/seeds/$name")
  fi

  printf "[%s] Running ... " "$name"
  set +e
  ASAN_OPTIONS="$asan_options" timeout "${timeout_seconds}s" "$fuzzer" \
    -artifact_prefix="${artifact_dir}/" \
    -max_total_time="$timeout_seconds" \
    "${dict_arg[@]}" \
    "$corpus_dir" \
    "${seed_arg[@]}" \
    >"$log_file" 2>&1
  rc=$?
  set -e

  if [[ $rc -eq 124 ]]; then
    echo "OK."
  elif [[ $rc -eq 0 ]]; then
    echo "OK."
  else
    echo "FAILED (exit code $rc, log: $log_file)"
    failure_count=$((failure_count + 1))
  fi
done

if [[ $failure_count -eq 0 ]]; then
  echo "All fuzzers completed successfully."
else
  echo "FAILURES: $failure_count harness(es) failed."
  exit 1
fi
