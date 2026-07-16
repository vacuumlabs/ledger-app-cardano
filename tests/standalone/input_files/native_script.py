# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Derive Native Script Hash check
"""

from dataclasses import dataclass

from tests.application_client.command_builder import (
    NativeScript,
    NativeScriptHashDisplayFormat,
    NativeScriptParamsInvalid,
    NativeScriptParamsNofK,
    NativeScriptParamsPubkey,
    NativeScriptParamsScripts,
    NativeScriptType,
)
from tests.application_client.status_words import StatusWord


@dataclass(frozen=True)
class NativeScriptExpectedResult:
    hash: str | None = None
    swo: StatusWord | None = StatusWord.SWO_SUCCESS


SignedData = NativeScriptExpectedResult


@dataclass(kw_only=True, frozen=True)
class ValidNativeScriptTestCase:
    name: str
    script: NativeScript | None = None
    displayFormat: NativeScriptHashDisplayFormat | None = NativeScriptHashDisplayFormat.BECH32
    unit_test_expect: NativeScriptExpectedResult | None = None
    ragger_expect: NativeScriptExpectedResult | None = None


# pylint: disable=line-too-long
ValidNativeScriptTestCases = [
    ValidNativeScriptTestCase(
        name="Native_script_PUBKEY_device_owned",
        script=NativeScript(
            NativeScriptType.PUBKEY_DEVICE_OWNED,
            NativeScriptParamsPubkey("m/1852'/1815'/0'/0/0"),
        ),
        unit_test_expect=SignedData("5102a193b3d5f0c256fcc425836ffb15e7d96d3389f5e57dc6bea726"),
        ragger_expect=SignedData(hash="e02316efa0632d53c28c521fc7bcade6e929849ff8b44efb5a2cffc0"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_PUBKEY_third_party",
        script=NativeScript(
            NativeScriptType.PUBKEY_THIRD_PARTY,
            NativeScriptParamsPubkey("3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"),
        ),
        unit_test_expect=SignedData("855228f5ecececf9c85618007cc3c2e5bdf5e6d41ef8d6fa793fe0eb"),
        ragger_expect=SignedData(hash="855228f5ecececf9c85618007cc3c2e5bdf5e6d41ef8d6fa793fe0eb"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_PUBKEY_third_party_script_hash_displayed_as_policy_id",
        script=NativeScript(
            NativeScriptType.PUBKEY_THIRD_PARTY,
            NativeScriptParamsPubkey("3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"),
        ),
        unit_test_expect=SignedData("855228f5ecececf9c85618007cc3c2e5bdf5e6d41ef8d6fa793fe0eb"),
        displayFormat=NativeScriptHashDisplayFormat.POLICY_ID,
        ragger_expect=SignedData(hash="855228f5ecececf9c85618007cc3c2e5bdf5e6d41ef8d6fa793fe0eb"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_ALL_script",
        script=NativeScript(
            NativeScriptType.ALL,
            NativeScriptParamsScripts(
                [
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey("c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"),
                    ),
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey("0241f2d196f52a92fbd2183d03b370c30b6960cfdeae364ffabac889"),
                    ),
                ]
            ),
        ),
        unit_test_expect=SignedData("af5c2ce476a6ede1c879f7b1909d6a0b96cb2081391712d4a355cef6"),
        ragger_expect=SignedData(hash="af5c2ce476a6ede1c879f7b1909d6a0b96cb2081391712d4a355cef6"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_ALL_script_no_subscripts",
        script=NativeScript(NativeScriptType.ALL, NativeScriptParamsScripts()),
        unit_test_expect=SignedData("d441227553a0f1a965fee7d60a0f724b368dd1bddbc208730fccebcf"),
        ragger_expect=SignedData(hash="d441227553a0f1a965fee7d60a0f724b368dd1bddbc208730fccebcf"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_ANY_script",
        script=NativeScript(
            NativeScriptType.ANY,
            NativeScriptParamsScripts(
                [
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey("c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"),
                    ),
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey("0241f2d196f52a92fbd2183d03b370c30b6960cfdeae364ffabac889"),
                    ),
                ]
            ),
        ),
        unit_test_expect=SignedData("d6428ec36719146b7b5fb3a2d5322ce702d32762b8c7eeeb797a20db"),
        ragger_expect=SignedData(hash="d6428ec36719146b7b5fb3a2d5322ce702d32762b8c7eeeb797a20db"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_ANY_script_no_subscripts",
        script=NativeScript(NativeScriptType.ANY, NativeScriptParamsScripts()),
        unit_test_expect=SignedData("52dc3d43b6d2465e96109ce75ab61abe5e9c1d8a3c9ce6ff8a3af528"),
        ragger_expect=SignedData(hash="52dc3d43b6d2465e96109ce75ab61abe5e9c1d8a3c9ce6ff8a3af528"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_N_OF_K_script",
        script=NativeScript(
            NativeScriptType.N_OF_K,
            NativeScriptParamsNofK(
                2,
                [
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey("c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"),
                    ),
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey("0241f2d196f52a92fbd2183d03b370c30b6960cfdeae364ffabac889"),
                    ),
                ],
            ),
        ),
        unit_test_expect=SignedData("78963f8baf8e6c99ed03e59763b24cf560bf12934ec3793eba83377b"),
        ragger_expect=SignedData(hash="78963f8baf8e6c99ed03e59763b24cf560bf12934ec3793eba83377b"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_N_OF_K_script_no_subscripts",
        script=NativeScript(NativeScriptType.N_OF_K, NativeScriptParamsNofK(0)),
        unit_test_expect=SignedData("3530cc9ae7f2895111a99b7a02184dd7c0cea7424f1632d73951b1d7"),
        ragger_expect=SignedData(hash="3530cc9ae7f2895111a99b7a02184dd7c0cea7424f1632d73951b1d7"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_INVALID_BEFORE_script",
        script=NativeScript(NativeScriptType.INVALID_BEFORE, NativeScriptParamsInvalid(42)),
        unit_test_expect=SignedData("2a25e608a683057e32ea38b50ce8875d5b34496b393da8d25d314c4e"),
        ragger_expect=SignedData(hash="2a25e608a683057e32ea38b50ce8875d5b34496b393da8d25d314c4e"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_INVALID_BEFORE_script_slot_is_a_big_number",
        script=NativeScript(
            NativeScriptType.INVALID_BEFORE,
            NativeScriptParamsInvalid(18446744073709551615),
        ),
        unit_test_expect=SignedData("d2469adac494849dd27d1b344b74cc6cd5bf31fbd01c879eae84c04b"),
        ragger_expect=SignedData(hash="d2469adac494849dd27d1b344b74cc6cd5bf31fbd01c879eae84c04b"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_INVALID_HEREAFTER_script",
        script=NativeScript(NativeScriptType.INVALID_HEREAFTER, NativeScriptParamsInvalid(42)),
        unit_test_expect=SignedData("1620dc65993296335183f23ff2f7747268168fabbeecbf24c8a20194"),
        ragger_expect=SignedData(hash="1620dc65993296335183f23ff2f7747268168fabbeecbf24c8a20194"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_INVALID_HEREAFTER_script_slot_is_a_big_number",
        script=NativeScript(
            NativeScriptType.INVALID_HEREAFTER,
            NativeScriptParamsInvalid(18446744073709551615),
        ),
        unit_test_expect=SignedData("da60fa40290f93b889a88750eb141fd2275e67a1255efb9bac251005"),
        ragger_expect=SignedData(hash="da60fa40290f93b889a88750eb141fd2275e67a1255efb9bac251005"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_Nested_native_scripts",
        script=NativeScript(
            NativeScriptType.ALL,
            NativeScriptParamsScripts(
                [
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey("c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"),
                    ),
                    NativeScript(
                        NativeScriptType.ANY,
                        NativeScriptParamsScripts(
                            [
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey("c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"),
                                ),
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey("0241f2d196f52a92fbd2183d03b370c30b6960cfdeae364ffabac889"),
                                ),
                            ]
                        ),
                    ),
                    NativeScript(
                        NativeScriptType.N_OF_K,
                        NativeScriptParamsNofK(
                            2,
                            [
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey("c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"),
                                ),
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey("0241f2d196f52a92fbd2183d03b370c30b6960cfdeae364ffabac889"),
                                ),
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey("cecb1d427c4ae436d28cc0f8ae9bb37501a5b77bcc64cd1693e9ae20"),
                                ),
                            ],
                        ),
                    ),
                    NativeScript(NativeScriptType.INVALID_BEFORE, NativeScriptParamsInvalid(100)),
                    NativeScript(
                        NativeScriptType.INVALID_HEREAFTER,
                        NativeScriptParamsInvalid(200),
                    ),
                ]
            ),
        ),
        unit_test_expect=SignedData("0d63e8d2c5a00cbcffbdf9112487c443466e1ea7d8c834df5ac5c425"),
        ragger_expect=SignedData(hash="0d63e8d2c5a00cbcffbdf9112487c443466e1ea7d8c834df5ac5c425"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_Nested native scripts #2",
        script=NativeScript(
            NativeScriptType.ALL,
            NativeScriptParamsScripts(
                [
                    NativeScript(
                        NativeScriptType.ANY,
                        NativeScriptParamsScripts(
                            [
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey("c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"),
                                ),
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey("0241f2d196f52a92fbd2183d03b370c30b6960cfdeae364ffabac889"),
                                ),
                            ]
                        ),
                    )
                ]
            ),
        ),
        unit_test_expect=SignedData("903e52ef2421abb11562329130330763583bb87cd98006b70ecb1b1c"),
        ragger_expect=SignedData(hash="903e52ef2421abb11562329130330763583bb87cd98006b70ecb1b1c"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_Nested native scripts #3",
        script=NativeScript(
            NativeScriptType.N_OF_K,
            NativeScriptParamsNofK(
                0,
                [
                    NativeScript(
                        NativeScriptType.ALL,
                        NativeScriptParamsScripts(
                            [
                                NativeScript(
                                    NativeScriptType.ANY,
                                    NativeScriptParamsScripts(
                                        [
                                            NativeScript(
                                                NativeScriptType.N_OF_K,
                                                NativeScriptParamsNofK(0),
                                            )
                                        ]
                                    ),
                                )
                            ]
                        ),
                    )
                ],
            ),
        ),
        unit_test_expect=SignedData("ed1dd7ef95caf389669c62618eb7f7aa7eadd08feb76618db2ae0cfc"),
        ragger_expect=SignedData(hash="ed1dd7ef95caf389669c62618eb7f7aa7eadd08feb76618db2ae0cfc"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_ALL_script_with_device_owned_pubkey",
        script=NativeScript(
            NativeScriptType.ALL,
            NativeScriptParamsScripts(
                [
                    NativeScript(
                        NativeScriptType.PUBKEY_DEVICE_OWNED,
                        NativeScriptParamsPubkey("m/1852'/1815'/0'/0/0"),
                    ),
                ]
            ),
        ),
        unit_test_expect=SignedData("b442025ae01ccb227ecbfc013d1c17eae7f8d04d366ffff5a091d03f"),
        ragger_expect=SignedData(hash="4bbf1d9a376372acd25fba87de0a9e6da080e8f51b1e7bc153917fe2"),
    ),
]

InvalidScriptTestCases = [
    ValidNativeScriptTestCase(
        name="Native_script_PUBKEY invalid key path",
        script=NativeScript(
            NativeScriptType.PUBKEY_DEVICE_OWNED,
            NativeScriptParamsPubkey("m/0/0/0/0/0/0"),
        ),
        unit_test_expect=NativeScriptExpectedResult(swo=StatusWord.SWO_NATIVE_SCRIPT_PARSING_FAIL_PUBKEY_CREDENTIAL),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_N_OF_K invalid required count higher than number of scripts",
        script=NativeScript(NativeScriptType.N_OF_K, NativeScriptParamsNofK(1)),
        unit_test_expect=NativeScriptExpectedResult(swo=StatusWord.SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_COUNT),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_PUBKEY_device_owned_path_invalid_non_hardened_account",
        # m/44'/1815'/0/0/0: account index 0 is not hardened, so bip44_classifyPath
        # returns PATH_INVALID and the security policy returns POLICY_DENY.
        script=NativeScript(
            NativeScriptType.PUBKEY_DEVICE_OWNED,
            NativeScriptParamsPubkey("m/44'/1815'/0/0/0"),
        ),
        unit_test_expect=NativeScriptExpectedResult(swo=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_N_OF_K_required_count_equals_zero_with_subscripts",
        # requiredCount=0 is valid but requiredCount=3 with 0 scripts is not.
        script=NativeScript(NativeScriptType.N_OF_K, NativeScriptParamsNofK(3)),
        unit_test_expect=NativeScriptExpectedResult(swo=StatusWord.SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_COUNT),
    ),
]
