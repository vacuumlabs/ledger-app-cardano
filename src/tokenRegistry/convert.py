# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

# converts entries from Cardano Token Registry (json) into code in C used in the app

import hashlib
import json
from pathlib import Path

# WARNING --- make sure that:
#     1. token tickers are meaningful and none is "(unknown decimals)"
#     2. buffers (e.g. tokenAmountStr) are big enough to hold the tickers
FILENAME = Path("tokenList.json")
OUTPUT_FILENAME = Path("token_data.csource")
MAX_DECIMALS = 255


def _fail(message):
    raise ValueError(message)


def _require(condition, message):
    if not condition:
        _fail(message)


def _escape_c_string(value):
    escaped_characters = []
    for character in value:
        codepoint = ord(character)
        _require(
            0x20 <= codepoint <= 0x7E,
            f"token label contains non-printable ASCII: {value!r}",
        )
        if character == "\\":
            escaped_characters.append("\\\\")
        elif character == '"':
            escaped_characters.append('\\"')
        else:
            escaped_characters.append(character)
    return "".join(escaped_characters)


def _normalize_asset_subject(asset_subject):
    _require(isinstance(asset_subject, str), "assetSubject must be a hex string")
    _require(len(asset_subject) % 2 == 0, "assetSubject hex string must have even length")
    try:
        return bytes.fromhex(asset_subject)
    except ValueError as exc:
        _fail(f"invalid assetSubject hex {asset_subject!r}: {exc}")


def _normalize_decimals(raw_decimals):
    _require(
        isinstance(raw_decimals, int) and not isinstance(raw_decimals, bool),
        "decimals must be an integer",
    )
    _require(
        0 <= raw_decimals <= MAX_DECIMALS,
        f"decimals must be in range 0..{MAX_DECIMALS}",
    )
    return raw_decimals


def _normalize_token_label(token_entry):
    ticker = token_entry.get("ticker")
    if isinstance(ticker, str) and len(ticker) > 0:
        label = ticker
    else:
        label = token_entry.get("name")

    _require(
        isinstance(label, str) and len(label) > 0,
        "token entry must contain a non-empty ticker or name",
    )
    return _escape_c_string(label)


def formatHexByte(b):
    return f"0x{b:02x}"


def bytestringToC(bstr):
    return "{ " + ", ".join([formatHexByte(b) for b in bstr]) + " }"


def tokenLine(tokenEntry):
    subject = _normalize_asset_subject(tokenEntry["assetSubject"])
    fingerprint = hashlib.blake2b(subject, digest_size=20).digest()
    decimals = _normalize_decimals(tokenEntry["decimals"])
    ticker = _normalize_token_label(tokenEntry)

    line = "{ "
    line += bytestringToC(fingerprint)
    line += ", "
    line += str(decimals)
    line += ", "
    line += '"' + ticker + '"'
    line += " }"
    return line


with FILENAME.open(encoding="utf-8") as input_file:
    registry = json.load(input_file)

allLines = ",\n".join([tokenLine(t) for t in registry])

with OUTPUT_FILENAME.open("w", encoding="utf-8") as outputFile:
    outputFile.write(allLines)
    outputFile.write("\n")
