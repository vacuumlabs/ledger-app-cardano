#!/usr/bin/env python3
"""Generate libFuzzer seed corpora for the Cardano app fuzzers from committed unit fixtures.

No ragger / device build needed. This reads the generated C fixture headers under
``tests/unit/generated/`` and reframes their APDU payloads into raw seed files under
``tests/fuzzing/seeds/<fuzzer>/``. Each seed is one (or, for the streaming harness, a
sequence of) full APDU(s) ``[CLA INS P1 P2 LC <payload>]`` — a real, valid input the
fuzzer starts from and mutates.

Two extraction modes:

* ``apdu_segment``  — parse ``apdu_segment_t NAME[] = { {.hex_payload="..", .p1=P1_X,
                      .p2=P2_Y}, ... }`` (sign_tx deny fixtures). Gives real per-segment
                      P1/P2 and complete APDU sequences.
* ``payload_array`` — parse ``static const uint8_t NAME[] = {0x.., ..};`` payload arrays
                      (pubkey / derive_address / opcert) and frame them with a fixed INS
                      and a default P1/P2 (these families do not encode P1/P2 in the array).

Run from anywhere:  python3 tests/fuzzing/generate_seed_corpus.py
"""

import re
import sys
from pathlib import Path

CLA = 0xD7

# INS codes (src/apdu/dispatcher.h)
INS_GET_PUBLIC_KEY = 0x10
INS_DERIVE_ADDRESS = 0x11
INS_DERIVE_NATIVE_SCRIPT_HASH = 0x12
INS_SIGN_TX = 0x21
INS_SIGN_OPCERT = 0x22
INS_SIGN_MSG = 0x24

# P1/P2 enum values used by the apdu_segment fixtures (src/apdu/dispatcher.h + handlers).
P_VALUES = {
    "P1_UNUSED": 0x00,
    "P2_UNUSED": 0x00,
    "P1_TX_SIGN_WITNESS": 0x0F,
    "P1_TX_INIT": 0x10,
    "P1_TX_CHUNK": 0x11,
    "P1_TX_CONFIRM": 0x12,
    "P1_TX_AUX_DATA": 0x13,
    "P2_AUX_DATA_INIT": 0x36,
    "P2_AUX_DATA_DELEGATION": 0x37,
    "P1_NATIVE_SCRIPT_INIT": 0x00,
    "P1_NATIVE_SCRIPT_START_COMPLEX": 0x01,
    "P1_NATIVE_SCRIPT_ADD_SIMPLE": 0x02,
    "P1_NATIVE_SCRIPT_FINISH": 0x03,
}

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / "tests" / "unit" / "generated"
SEED_ROOT = Path(__file__).resolve().parent / "seeds"

# What to extract for each harness.
#   mode="apdu_segment": files with apdu_segment_t arrays; emit="segment" (one APDU per
#                        segment) or "sequence" (whole array concatenated).
#   mode="payload_array": raw uint8_t payload arrays whose name ends with `suffix`.
CONFIGS = [
    {
        "harness": "fuzz_signTx",
        "mode": "apdu_segment",
        "ins": INS_SIGN_TX,
        "glob": "sign_tx/*.h",
        "emit": "segment",
    },
    {
        "harness": "fuzz_all_handlers",
        "mode": "apdu_segment",
        "ins": INS_SIGN_TX,
        "glob": "sign_tx/*.h",
        "emit": "sequence",
    },
    {
        "harness": "fuzz_getPublicKeys",
        "mode": "payload_array",
        "ins": INS_GET_PUBLIC_KEY,
        "p1": 0x00,
        "p2": 0x00,
        "glob": "pubkey/*.h",
        "suffix": "_APDU",
    },
    {
        "harness": "fuzz_deriveAddress",
        "mode": "payload_array",
        "ins": INS_DERIVE_ADDRESS,
        "p1": 0x01,  # P1_ADDRESS_RETURN
        "p2": 0x00,
        "glob": "derive_address/*.h",
        "suffix": "_APDU",
    },
    {
        "harness": "fuzz_signOpCert",
        "mode": "payload_array",
        "ins": INS_SIGN_OPCERT,
        "p1": 0x00,
        "p2": 0x00,
        "glob": "opcert/*.h",
        "suffix": "_PAYLOAD",
    },
    {
        # native script: P1 lives in a `// APDU payload for P1_X` comment above each array.
        "harness": "fuzz_deriveNativeScriptHash",
        "mode": "payload_p1_comment",
        "ins": INS_DERIVE_NATIVE_SCRIPT_HASH,
        "glob": "native_script/*.h",
    },
    {
        # cvote aux parser is NOT APDU-framed: it consumes the raw init payload directly.
        "harness": "fuzz_cvote_aux_parser",
        "mode": "raw",
        "glob": "cvote/*.h",
        "suffix": "_INIT_APDU",
    },
    {
        # sign_msg has no dedicated harness; feed its APDUs to the combined dispatcher.
        "harness": "fuzz_all_handlers",
        "mode": "payload_p1_name",
        "ins": INS_SIGN_MSG,
        "glob": "sign_msg/*.h",
        "suffix": "_APDU",
    },
]

_SEGMENT_ARRAY_RE = re.compile(r"apdu_segment_t\s+(\w+)\s*\[\]\s*=\s*\{(.*?)\n\};", re.DOTALL)
_SEGMENT_RE = re.compile(r"\{(.*?)\}", re.DOTALL)
_HEX_RE = re.compile(r'\.hex_payload\s*=\s*((?:"(?:[^"\\]|\\.)*"\s*)+)', re.DOTALL)
_P1_RE = re.compile(r"\.p1\s*=\s*(\w+)")
_P2_RE = re.compile(r"\.p2\s*=\s*(\w+)")
_STR_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_PAYLOAD_ARRAY_RE = re.compile(r"static\s+const\s+uint8_t\s+(\w+)\s*\[\]\s*=\s*\{([^}]*)\};", re.DOTALL)
_BYTE_RE = re.compile(r"0x([0-9A-Fa-f]{1,2})")
_P1_COMMENT_RE = re.compile(r"// APDU payload for (P1_\w+)")


def _p_value(name: str) -> int:
    if name not in P_VALUES:
        raise KeyError(f"Unknown P1/P2 symbol {name!r}; add it to P_VALUES")
    return P_VALUES[name]


def _frame(ins: int, p1: int, p2: int, payload: bytes) -> bytes | None:
    """Build a full APDU [CLA INS P1 P2 LC payload]; None if payload can't fit one APDU."""
    if len(payload) > 0xFF:
        return None  # cannot be a single short-form APDU
    return bytes([CLA, ins, p1, p2, len(payload)]) + payload


def _parse_segments(text: str):
    """Yield (array_name, [(payload_bytes, p1, p2), ...]) for each apdu_segment_t array."""
    for name, body in _SEGMENT_ARRAY_RE.findall(text):
        segments = []
        for seg in _SEGMENT_RE.findall(body):
            hexm = _HEX_RE.search(seg)
            p1m = _P1_RE.search(seg)
            p2m = _P2_RE.search(seg)
            if not (hexm and p1m and p2m):
                continue
            hex_str = "".join(_STR_LITERAL_RE.findall(hexm.group(1)))
            payload = bytes.fromhex(hex_str)
            segments.append((payload, _p_value(p1m.group(1)), _p_value(p2m.group(1))))
        if segments:
            yield name, segments


def _parse_payload_arrays(text: str, suffix: str):
    """Yield (array_name, payload_bytes) for uint8_t arrays whose name ends with suffix."""
    for name, body in _PAYLOAD_ARRAY_RE.findall(text):
        if not name.endswith(suffix) or "EXPECTED" in name:
            continue
        payload = bytes(int(b, 16) for b in _BYTE_RE.findall(body))
        if payload:
            yield name, payload


def _write(out_dir: Path, index: int, name: str, data: bytes) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    short = name.lower()[:60]
    (out_dir / f"{index:03d}_{short}").write_bytes(data)


def main() -> int:
    if not FIXTURE_ROOT.is_dir():
        print(f"ERROR: fixtures not found at {FIXTURE_ROOT}", file=sys.stderr)
        return 1

    total = 0
    for cfg in CONFIGS:
        out_dir = SEED_ROOT / cfg["harness"]
        files = sorted(FIXTURE_ROOT.glob(cfg["glob"]))
        count = 0
        idx = 0
        for fpath in files:
            text = fpath.read_text()
            if cfg["mode"] == "apdu_segment":
                for name, segments in _parse_segments(text):
                    if cfg["emit"] == "sequence":
                        blob = b""
                        for payload, p1, p2 in segments:
                            apdu = _frame(cfg["ins"], p1, p2, payload)
                            if apdu is None:
                                blob = b""
                                break
                            blob += apdu
                        if blob:
                            _write(out_dir, idx, name, blob)
                            idx += 1
                            count += 1
                    else:  # one seed per segment
                        for si, (payload, p1, p2) in enumerate(segments):
                            apdu = _frame(cfg["ins"], p1, p2, payload)
                            if apdu is not None:
                                _write(out_dir, idx, f"{name}_{si}", apdu)
                                idx += 1
                                count += 1
            elif cfg["mode"] == "payload_array":
                for name, payload in _parse_payload_arrays(text, cfg["suffix"]):
                    apdu = _frame(cfg["ins"], cfg["p1"], cfg["p2"], payload)
                    if apdu is not None:
                        _write(out_dir, idx, name, apdu)
                        idx += 1
                        count += 1
            elif cfg["mode"] == "raw":
                # Harness feeds the bytes straight to the parser — no APDU framing.
                for name, payload in _parse_payload_arrays(text, cfg["suffix"]):
                    _write(out_dir, idx, name, payload)
                    idx += 1
                    count += 1
            elif cfg["mode"] == "payload_p1_name":
                for name, payload in _parse_payload_arrays(text, cfg["suffix"]):
                    if "_INIT_" in name:
                        p1 = 0x01
                    elif "_CHUNK_" in name:
                        p1 = 0x02
                    elif "_CONFIRM_" in name:
                        p1 = 0x03
                    else:
                        p1 = 0x00
                    apdu = _frame(cfg["ins"], p1, 0x00, payload)
                    if apdu is not None:
                        _write(out_dir, idx, name, apdu)
                        idx += 1
                        count += 1
            elif cfg["mode"] == "payload_p1_comment":
                comments = [(m.start(), m.group(1)) for m in _P1_COMMENT_RE.finditer(text)]
                for m in _PAYLOAD_ARRAY_RE.finditer(text):
                    name, body = m.group(1), m.group(2)
                    if "APDU_PAYLOAD" not in name or "EXPECTED" in name:
                        continue
                    p1_name = None
                    for pos, p1sym in comments:
                        if pos < m.start():
                            p1_name = p1sym
                        else:
                            break
                    if p1_name is None:
                        continue
                    payload = bytes(int(b, 16) for b in _BYTE_RE.findall(body))
                    if not payload:
                        continue
                    apdu = _frame(cfg["ins"], _p_value(p1_name), 0x00, payload)
                    if apdu is not None:
                        _write(out_dir, idx, name, apdu)
                        idx += 1
                        count += 1
        print(f"{cfg['harness']:<32} {count:>4} seeds  <- {cfg['glob']}")
        total += count

    print(f"\nTotal: {total} seed files under {SEED_ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
