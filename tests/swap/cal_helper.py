# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from ledger_app_clients.exchange.cal_helper import CurrencyConfiguration
from ragger.utils import create_currency_config

# Packed derivation path for m/1852'/1815'/0'/0/0 (Shelley standard)
# Format: 1 byte length (5) + 5 * 4 bytes big-endian path components
ADA_SHELLEY_PACKED_DERIVATION_PATH = bytes(
    [
        5,  # path length
        0x80,
        0x00,
        0x07,
        0x3C,  # 1852' (0x8000073C)
        0x80,
        0x00,
        0x07,
        0x17,  # 1815' (0x80000717)
        0x80,
        0x00,
        0x00,
        0x00,  # 0'    (0x80000000)
        0x00,
        0x00,
        0x00,
        0x00,  # 0
        0x00,
        0x00,
        0x00,
        0x00,  # 0
    ]
)

ADA_CONF = create_currency_config("ADA", "Cardano ADA")

ADA_SHELLEY_CURRENCY_CONFIGURATION = CurrencyConfiguration(
    ticker="ADA",
    conf=ADA_CONF,
    packed_derivation_path=ADA_SHELLEY_PACKED_DERIVATION_PATH,
)
