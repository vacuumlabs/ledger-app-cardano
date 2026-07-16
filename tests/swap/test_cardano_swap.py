# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import sys
import time

import pytest
from ledger_app_clients.exchange.test_runner import (
    ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES,
    ExchangeTestRunner,
)
from ledger_app_clients.exchange.utils import handle_lib_call_start_or_stop
from ragger.error import ExceptionRAPDU

import bech32
from tests.application_client.command_builder import (
    AddressParams,
    AddressType,
    Mainnet,
    ThirdPartyAddressParams,
    Transaction,
    TransactionSigningMode,
    TxInput,
    TxOutputAlonzo,
    TxOutputBabbage,
    TxOutputDestination,
    TxOutputDestinationType,
    TxOutputFormat,
    gather_witness_paths,
)
from tests.application_client.command_sender import CommandSender
from tests.application_client.status_words import StatusWord

from . import cal_helper as cal

# Swap checking fail error code returned by the app
SWO_SWAP_CHECKING_FAIL = 0x6001
ED25519_SIGNATURE_LENGTH = 64


class CardanoShelleySwapTests(ExchangeTestRunner):
    # ADA currency configuration for the Exchange test runner
    currency_configuration = cal.ADA_SHELLEY_CURRENCY_CONFIGURATION

    # Valid destination addresses (bech32 mainnet Shelley addresses)
    valid_destination_1 = (
        "addr1q80r70qggedqy90z4rzy6kynv4xqejxfxqmangwhz8ugalfwlqyt4mswmh4hl0nnq53r4rp798vj4c7p7f2wdgqnc8uqt2xltv"  # pylint: disable=line-too-long
    )
    valid_destination_2 = (
        "addr1q84sh2j72ux0l03fxndjnhctdg7hcppsaejafsa84vh7lwgmcs5wgus8qt4atk45lvt4xfxpjtwfhdmvchdf2m3u3hlsd5tq5r"  # pylint: disable=line-too-long
    )

    # Refund address (device-owned, derived from Speculos seed at m/1852'/1815'/0'/0/0)
    valid_refund = "addr1q9kl5z2zd9vakyprvw0g68c8hv0y0rnj93htc82hh2rs8wwmyx0wtn56wnuclkku9hsnal8dtg25a7x56svjn4dlnlmq7quz6p"  # pylint: disable=line-too-long
    valid_refund_memo = ""
    valid_destination_memo_1 = ""
    valid_destination_memo_2 = ""

    # Amounts in lovelace (smallest ADA unit)
    valid_send_amount_1 = 4671693
    valid_send_amount_2 = 446739662
    valid_fees_1 = 174345
    valid_fees_2 = 28

    # Fake addresses for denial testing
    fake_refund = "abcdabcd"
    fake_refund_memo = ""
    fake_payout = "abcdabcd"
    fake_payout_memo = ""

    # Error code the app returns when swap validation fails
    signature_refusal_error_code = SWO_SWAP_CHECKING_FAIL

    def perform_coin_specific_final_tx(self, destination, send_amount, fees, memo):
        """Run final Cardano signing without letting post-sign snapshots hide APDU failures."""
        primary_exception_info = None
        post_sign_exception_info = None

        try:
            self.perform_final_tx(destination, send_amount, fees, memo)
        except Exception:  # pylint: disable=broad-exception-caught
            primary_exception_info = sys.exc_info()

        try:
            self.exchange_navigation_helper.check_post_sign_display()
        except Exception:  # pylint: disable=broad-exception-caught
            post_sign_exception_info = sys.exc_info()
        finally:
            try:
                handle_lib_call_start_or_stop(self.backend)
            except Exception:  # pylint: disable=broad-exception-caught
                if primary_exception_info is None and post_sign_exception_info is None:
                    raise

        if primary_exception_info is not None:
            _, exception, traceback = primary_exception_info
            raise exception.with_traceback(traceback)

        if post_sign_exception_info is not None:
            _, exception, traceback = post_sign_exception_info
            raise exception.with_traceback(traceback)

    def _assert_exchange_started_with_retry(self):
        # In negative library paths, GET_VERSION may briefly return SWO_SWAP_CHECKING_FAIL
        # until the app returns from os_lib_end to Exchange.
        for _ in range(6):
            try:
                self.assert_exchange_is_started()
                return
            except ExceptionRAPDU as e:
                if e.status != SWO_SWAP_CHECKING_FAIL:
                    raise
                time.sleep(0.2)
        self.assert_exchange_is_started()

    def _destination_to_hex(self, destination: str) -> str:
        _, data_part = bech32.bech32_decode(destination)
        if data_part is None:
            # Not a valid bech32 address - pass as-is for denial testing
            return destination.encode().hex()
        converted = bech32.convertbits(data_part, 5, 8, False)
        assert converted is not None, "bech32.convertbits returned None"
        destination_bytes = bytes(converted)
        return destination_bytes.hex()

    def _build_swap_tx(
        self,
        destination: str,
        send_amount: int,
        fees: int,
        third_party_output_count: int = 1,
    ) -> Transaction:
        destination_hex = self._destination_to_hex(destination)

        # Balance the mock tx body according to how many THIRD_PARTY outputs we include.
        input_amount = send_amount * third_party_output_count + fees + 2000000
        change_amount = input_amount - send_amount * third_party_output_count - fees

        outputs: list[TxOutputAlonzo | TxOutputBabbage] = []
        for _ in range(third_party_output_count):
            outputs.append(
                TxOutputBabbage(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.THIRD_PARTY,
                        params=ThirdPartyAddressParams(
                            addressHex=destination_hex,
                        ),
                    ),
                    amount=send_amount,
                    format=TxOutputFormat.MAP_BABBAGE,
                )
            )

        outputs.append(
            TxOutputBabbage(
                destination=TxOutputDestination(
                    type=TxOutputDestinationType.DEVICE_OWNED,
                    params=AddressParams(
                        netDesc=Mainnet,
                        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
                        spendingValue="m/1852'/1815'/0'/1/0",
                        stakingValue="m/1852'/1815'/0'/2/0",
                    ),
                ),
                amount=change_amount,
                format=TxOutputFormat.MAP_BABBAGE,
            )
        )

        return Transaction(
            network=Mainnet,
            inputs=[
                TxInput(
                    txHashHex="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
                    path="m/1852'/1815'/0'/0/0",
                    outputIndex=0,
                ),
            ],
            outputs=outputs,
            fee=fees,
            ttl=100000000,
        )

    def perform_final_tx(self, destination, send_amount, fees, memo):  # pylint: disable=unused-argument
        """Build and sign a standard Cardano transaction for swap finalization."""
        tx = self._build_swap_tx(destination, send_amount, fees, third_party_output_count=1)
        client = CommandSender(self.backend)

        # In swap mode, no UI review is needed (on_review=None)
        client.sign_tx(
            tx,
            TransactionSigningMode.ORDINARY,
            on_review=None,
        )

        # Swap flow is completed only after all witnesses are requested and signed.
        witness_paths = gather_witness_paths(tx, TransactionSigningMode.ORDINARY, [])
        assert witness_paths, "Expected at least one witness path for swap final transaction"
        for witness_path in witness_paths:
            witness_response = client.sign_tx_witness(witness_path)

        assert witness_response.status == StatusWord.SWO_SUCCESS
        assert len(witness_response.data) == ED25519_SIGNATURE_LENGTH


class CardanoShelleySwapDenyMultipleThirdPartyOutputs(CardanoShelleySwapTests):
    def perform_final_tx(self, destination, send_amount, fees, memo):  # pylint: disable=unused-argument
        tx = self._build_swap_tx(destination, send_amount, fees, third_party_output_count=2)
        client = CommandSender(self.backend)

        # Must be denied in swap mode with SWO_SWAP_CHECKING_FAIL.
        client.sign_tx(
            tx,
            TransactionSigningMode.ORDINARY,
            on_review=None,
        )

    def perform_test_swap_deny_multiple_third_party_outputs(self):
        self.perform_valid_swap_from_custom(
            self.valid_destination_1,
            self.valid_send_amount_1,
            self.valid_fees_1,
            self.valid_destination_memo_1,
        )
        with pytest.raises(ExceptionRAPDU) as e:
            self.perform_final_tx(
                self.valid_destination_1,
                self.valid_send_amount_1,
                self.valid_fees_1,
                self.valid_destination_memo_1,
            )
        assert e.value.status == self.wrong_destination_error_code
        handle_lib_call_start_or_stop(self.backend)
        self._assert_exchange_started_with_retry()


class CardanoShelleySwapDenyWitnessPoolColdPath(CardanoShelleySwapTests):
    def perform_final_tx(self, destination, send_amount, fees, memo):  # pylint: disable=unused-argument
        tx = self._build_swap_tx(destination, send_amount, fees, third_party_output_count=1)
        client = CommandSender(self.backend)

        # Pool cold key is denied in swap witness policy.
        denied_witness_path = "m/1853'/1815'/0'/0'"
        client.sign_tx(
            tx,
            TransactionSigningMode.ORDINARY,
            additional_witness_paths=[denied_witness_path],
            on_review=None,
        )

        witness_paths = gather_witness_paths(
            tx,
            TransactionSigningMode.ORDINARY,
            [denied_witness_path],
        )
        for witness_path in witness_paths:
            client.sign_tx_witness(witness_path)

    def perform_test_swap_deny_witness_pool_cold_path(self):
        self.perform_valid_swap_from_custom(
            self.valid_destination_1,
            self.valid_send_amount_1,
            self.valid_fees_1,
            self.valid_destination_memo_1,
        )
        with pytest.raises(ExceptionRAPDU) as e:
            self.perform_final_tx(
                self.valid_destination_1,
                self.valid_send_amount_1,
                self.valid_fees_1,
                self.valid_destination_memo_1,
            )
        assert e.value.status == SWO_SWAP_CHECKING_FAIL
        handle_lib_call_start_or_stop(self.backend)
        self._assert_exchange_started_with_retry()


# We use a class to reuse the same Speculos instance (faster performances)
class TestsCardanoSwap:
    @pytest.mark.parametrize("test_to_run", ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES)
    def test_cardano_swap(self, backend, exchange_navigation_helper, test_to_run):
        CardanoShelleySwapTests(backend, exchange_navigation_helper).run_test(test_to_run)

    def test_cardano_swap_deny_multiple_third_party_outputs(self, backend, exchange_navigation_helper):
        CardanoShelleySwapDenyMultipleThirdPartyOutputs(
            backend,
            exchange_navigation_helper,
        ).run_test("swap_deny_multiple_third_party_outputs")

    def test_cardano_swap_deny_witness_pool_cold_path(
        self,
        backend,
        exchange_navigation_helper,
    ):
        CardanoShelleySwapDenyWitnessPoolColdPath(
            backend,
            exchange_navigation_helper,
        ).run_test("swap_deny_witness_pool_cold_path")
