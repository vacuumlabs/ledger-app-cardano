# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from typing import Callable, Generator, Optional, Sequence
from contextlib import contextmanager

from ragger.backend.interface import BackendInterface, RAPDU
from ragger.error import ExceptionRAPDU

from tests.application_client.command_builder import (
    AddressParams,
    CommandBuilder,
    CVoteTestCase,
    NativeScript,
    NativeScriptHashDisplayFormat,
    OpCertTestCase,
    SETTINGS_DISABLED,
    SETTINGS_ENABLED,
    Transaction,
    TxAuxiliaryDataCIP36,
    TxAuxiliaryDataType,
    gather_witness_paths,
)
from tests.application_client.response_unpacker import (
    GetVersionResponse,
    unpack_derive_address_response,
    unpack_get_version_response,
    unpack_sign_message_response,
    unpack_sign_tx_aux_data_confirm_response,
    unpack_sign_tx_hash_response,
)
from tests.application_client.status_words import StatusWord


class CommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend
        self._cmd_builder = CommandBuilder()

    def _exchange(self, payload: bytes) -> RAPDU:
        """Synchronous APDU exchange with response

        Args:
            payload (bytes): APDU data to send

        Returns:
            Response APDU
        """

        return self.backend.exchange_raw(payload)

    @contextmanager
    def _exchange_async(self, payload: bytes) -> Generator[bool, None, None]:
        """Asynchronous APDU exchange with response

        Args:
            payload (bytes): APDU data to send

        Returns:
            Generator
        """

        with self.backend.exchange_async_raw(payload) as has_data_available:
            assert has_data_available is not None
            yield has_data_available

    def get_async_response(self) -> Optional[RAPDU]:
        """Asynchronous APDU response

        Returns:
            Response APDU
        """

        return self.backend.last_async_response

    def get_version_raw(self) -> RAPDU:
        return self._exchange(self._cmd_builder.get_version())

    def get_version(self) -> GetVersionResponse:
        response = self.get_version_raw()
        if response.status != StatusWord.SWO_SUCCESS:
            raise AssertionError(f"GET_VERSION failed: {hex(response.status)}")
        return unpack_get_version_response(response.data)

    def get_app_name(self) -> RAPDU:
        return self._exchange(self._cmd_builder.get_app_name())

    def get_serial(self) -> RAPDU:
        return self._exchange(self._cmd_builder.get_serial())

    @contextmanager
    def get_pubkey_async(self, path: str) -> Generator[None, None, None]:
        with self._exchange_async(self._cmd_builder.get_pubkey_path(path)):
            yield

    @contextmanager
    def sign_opcert_async(
        self, test_case: OpCertTestCase
    ) -> Generator[None, None, None]:
        """APDU Sign Operational Certificate

        Args:
            test_case (OpCertTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_opcert(test_case)):
            yield

    @contextmanager
    def sign_tx_witness_async(self, path: str) -> Generator[bool, None, None]:
        """APDU Sign TX Witness

        Args:
            path (str): BIP44 derivation path

        Returns:
            Generator
        """

        with self._exchange_async(
            self._cmd_builder.sign_tx_witness(path)
        ) as has_data_available:
            yield has_data_available

    def sign_tx(
        self,
        tx: Transaction,
        signing_mode: int,
        additional_witness_paths: Optional[Sequence[str]] = None,
        options: int = 0,
        on_review: Optional[Callable[[], None]] = None,
        on_cvote_review: Optional[Callable[[], None]] = None,
        on_advance: Optional[Callable[[int], None]] = None,
    ) -> tuple[bytes, Optional[tuple[bytes, bytes]]]:
        """Sign a transaction and return (tx_hash, cip36_aux_data).

        cip36_aux_data is (aux_data_hash, registration_signature) when the
        transaction carries a CIP36 registration, otherwise None.
        """
        extra_paths = additional_witness_paths or []
        witness_paths = gather_witness_paths(tx, signing_mode, extra_paths)

        init_params = self._cmd_builder.build_tx_init_params(
            tx=tx,
            signing_mode=signing_mode,
            witness_paths=witness_paths,
            options=options,
        )
        response = self._exchange(self._cmd_builder.sign_tx_init(init_params))
        if response.status != StatusWord.SWO_SUCCESS:
            raise AssertionError(f"Init failed: {hex(response.status)}")

        cip36_aux_data = self._send_tx_aux_data_if_present(
            tx, on_cvote_review, on_advance
        )

        with self.sign_tx_send_chunks_async(tx) as has_data_available:
            if on_review is not None and not has_data_available:
                on_review()

        final_response = self.get_async_response()
        if final_response is None:
            raise AssertionError("No response from final chunk")
        if final_response.status != StatusWord.SWO_SUCCESS:
            raise AssertionError(f"Transaction failed: {hex(final_response.status)}")

        return unpack_sign_tx_hash_response(final_response.data), cip36_aux_data

    def _send_tx_aux_data_if_present(
        self,
        tx: Transaction,
        on_review: Optional[Callable[[], None]] = None,
        on_advance: Optional[Callable[[int], None]] = None,
    ) -> Optional[tuple[bytes, bytes]]:
        """Send CIP36 auxiliary data APDUs if present.

        Returns (aux_data_hash, registration_signature) if CIP36 registration
        was processed, otherwise None.
        """
        if tx.auxiliaryData is None:
            return None
        if tx.auxiliaryData.type != TxAuxiliaryDataType.CIP36_REGISTRATION:
            return None

        aux_params = tx.auxiliaryData.params
        if not isinstance(aux_params, TxAuxiliaryDataCIP36):
            raise AssertionError("Unexpected auxiliary data params type")

        has_delegations = len(aux_params.delegations) > 0

        if has_delegations:
            if on_advance:
                with self._exchange_async(
                    self._cmd_builder.sign_tx_aux_data_init(aux_params)
                ) as has_data_available:
                    if not has_data_available:
                        on_advance(2)
                response = self.get_async_response()
                if response is None:
                    raise AssertionError("No response from AUX_DATA init")
            else:
                response = self._exchange(
                    self._cmd_builder.sign_tx_aux_data_init(aux_params)
                )
            if response.status != StatusWord.SWO_SUCCESS:
                raise AssertionError(f"AUX_DATA init failed: {hex(response.status)}")

            for delegation in aux_params.delegations[:-1]:
                if on_advance:
                    with self._exchange_async(
                        self._cmd_builder.sign_tx_aux_data_delegation(delegation)
                    ) as has_data_available:
                        if not has_data_available:
                            on_advance(1)
                    response = self.get_async_response()
                    if response is None:
                        raise AssertionError("No response from AUX_DATA delegation")
                else:
                    response = self._exchange(
                        self._cmd_builder.sign_tx_aux_data_delegation(delegation)
                    )
                if response.status != StatusWord.SWO_SUCCESS:
                    raise AssertionError(
                        f"AUX_DATA registration failed: {hex(response.status)}"
                    )

            last_delegation = aux_params.delegations[-1]
            with self._exchange_async(
                self._cmd_builder.sign_tx_aux_data_delegation(last_delegation)
            ) as has_data_available:
                if on_review and not has_data_available:
                    on_review()

            response = self.get_async_response()
            if response is None:
                raise AssertionError("No response from last delegation")
            if response.status != StatusWord.SWO_SUCCESS:
                raise AssertionError(
                    f"AUX_DATA registration failed: {hex(response.status)}"
                )
        else:
            with self._exchange_async(
                self._cmd_builder.sign_tx_aux_data_init(aux_params)
            ) as has_data_available:
                if on_review and not has_data_available:
                    on_review()

            response = self.get_async_response()
            if response is None:
                raise AssertionError("No response from AUX_DATA init")
            if response.status != StatusWord.SWO_SUCCESS:
                raise AssertionError(f"AUX_DATA init failed: {hex(response.status)}")

        return unpack_sign_tx_aux_data_confirm_response(response.data)

    @contextmanager
    def sign_tx_send_chunks_async(self, tx) -> Generator[bool, None, None]:
        """Serialize transaction into chunks and send them.

        Sends all intermediate chunks synchronously, then the final chunk asynchronously
        for UI navigation.

        Args:
            tx: Transaction object from signTx.py

        Returns:
            Generator (use with 'with' statement for navigation)
        """
        chunks = self._cmd_builder.serialize_transaction_chunks(tx)

        # Send all intermediate chunks synchronously
        for chunk in chunks[:-1]:
            response = self._exchange(chunk)
            if response.status != StatusWord.SWO_SUCCESS:
                raise AssertionError(
                    f"Intermediate chunk failed: {hex(response.status)}"
                )

        # Send final chunk asynchronously (for UI navigation)
        with self._exchange_async(chunks[-1]) as has_data_available:
            yield has_data_available

    def sign_tx_witness(self, path: str) -> RAPDU:
        """APDU Sign TX Witness (synchronous)

        Args:
            path (str): BIP44 derivation path for witness

        Returns:
            Response APDU with signature
        """
        return self._exchange(self._cmd_builder.sign_tx_witness(path))

    def set_debug_settings(
        self, expert_mode: bool, silent_export: bool, blind_signing: bool
    ) -> RAPDU:
        """Set app settings via debug APDU (only works with DEBUG builds).

        This is a debug-only command that allows tests to programmatically set
        app settings without UI navigation. It only works when the app is built
        with DEBUG=1 flag.

        Args:
            expert_mode: True to enable expert mode, False to disable
            silent_export: True to enable silent pubkey export, False to disable
            blind_signing: True to enable blind signing, False to disable

        Returns:
            Response APDU with current settings as confirmation (3 bytes)

        Raises:
            AssertionError: If the command fails or returns unexpected status
        """
        response = self.try_set_debug_settings(
            expert_mode, silent_export, blind_signing
        )

        if response.status != StatusWord.SWO_SUCCESS:
            raise AssertionError(f"Debug set settings failed: {hex(response.status)}")

        # Verify response contains 3 bytes (current settings)
        if len(response.data) != 3:
            raise AssertionError(
                f"Expected 3 bytes in response, got {len(response.data)}"
            )

        # Verify settings were applied correctly
        actual_expert = response.data[0]
        actual_silent = response.data[1]
        actual_blind_signing = response.data[2]
        expected_expert = SETTINGS_ENABLED if expert_mode else SETTINGS_DISABLED
        expected_silent = SETTINGS_ENABLED if silent_export else SETTINGS_DISABLED
        expected_blind_signing = (
            SETTINGS_ENABLED if blind_signing else SETTINGS_DISABLED
        )

        if (
            actual_expert != expected_expert
            or actual_silent != expected_silent
            or actual_blind_signing != expected_blind_signing
        ):
            raise AssertionError(
                "Settings mismatch: "
                f"expected expert={expected_expert}, silent={expected_silent}, blind={expected_blind_signing}, "
                f"got expert={actual_expert}, silent={actual_silent}, blind={actual_blind_signing}"
            )

        return response

    def try_set_debug_settings(
        self, expert_mode: bool, silent_export: bool, blind_signing: bool
    ) -> RAPDU:
        """Send the debug settings APDU and return the raw response."""
        try:
            return self._exchange(
                self._cmd_builder.debug_set_settings(
                    expert_mode, silent_export, blind_signing
                )
            )
        except ExceptionRAPDU as err:
            return RAPDU(data=err.data, status=err.status)

    @contextmanager
    def derive_address_async(
        self, p1: int, test_case_params: AddressParams
    ) -> Generator[None, None, None]:
        """APDU Derive Address

        Args:
            p1 (int): APDU Parameter 1
            test_case_params (AddressParams): Address parameters

        Returns:
            Generator
        """

        with self._exchange_async(
            self._cmd_builder.derive_address(p1, test_case_params)
        ):
            yield

    def derive_address(self, p1: int, test_case_params: AddressParams) -> bytes:
        """APDU Derive Address

        Args:
            p1 (int): APDU Parameter 1
            test_case_params (AddressParams): Address parameters

        Returns:
            Raw address bytes
        """

        response = self._exchange(
            self._cmd_builder.derive_address(p1, test_case_params)
        )
        if response.status != StatusWord.SWO_SUCCESS:
            raise AssertionError(f"Derive address failed: {hex(response.status)}")
        return unpack_derive_address_response(response.data)

    @contextmanager
    def derive_script_add_simple_async(
        self, script: NativeScript
    ) -> Generator[bool, None, None]:
        """APDU NATIVE SCRIPT HASH - SIMPLE SCRIPT step

        Args:
            script (NativeScript): Input Test param

        Returns:
            Generator
        """

        with self._exchange_async(
            self._cmd_builder.derive_script_add_simple(script)
        ) as has_data_available:
            yield has_data_available

    @contextmanager
    def derive_script_init_async(self) -> Generator[bool, None, None]:
        """APDU NATIVE SCRIPT HASH - INIT step"""
        with self._exchange_async(
            self._cmd_builder.derive_script_init()
        ) as has_data_available:
            yield has_data_available

    @contextmanager
    def derive_script_add_complex_async(
        self, script: NativeScript
    ) -> Generator[bool, None, None]:
        """APDU NATIVE SCRIPT HASH - COMPLEX SCRIPT step

        Args:
            script (NativeScript): Input Test param

        Returns:
            Generator
        """

        with self._exchange_async(
            self._cmd_builder.derive_script_add_complex(script)
        ) as has_data_available:
            yield has_data_available

    @contextmanager
    def derive_script_finish_async(
        self, display_format: NativeScriptHashDisplayFormat
    ) -> Generator[bool, None, None]:
        """APDU NATIVE SCRIPT HASH - FINISH step

        Args:
            display_format (NativeScriptHashDisplayFormat): Input Test param

        Returns:
            Generator
        """

        with self._exchange_async(
            self._cmd_builder.derive_script_finish(display_format)
        ) as has_data_available:
            yield has_data_available

    @contextmanager
    def sign_cip36_init_async(
        self, testCase: CVoteTestCase
    ) -> Generator[None, None, None]:
        """APDU CIP36 Vote - INIT step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_cvote_init(testCase)):
            yield

    def has_sign_cip36_chunks(self, testCase: CVoteTestCase) -> bool:
        return len(self._cmd_builder.sign_cvote_chunk(testCase)) > 0

    def sign_cip36_chunk(self, testCase: CVoteTestCase) -> RAPDU:
        """APDU CIP36 Vote - CHUNK step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Response APDU
        """

        chunks = self._cmd_builder.sign_cvote_chunk(testCase)
        if not chunks:
            raise AssertionError("No CIP-36 CHUNK APDUs to send")

        for chunk in chunks[:-1]:
            resp = self._exchange(chunk)
            if resp.status != StatusWord.SWO_SUCCESS:
                raise AssertionError(f"CIP-36 chunk failed: {hex(resp.status)}")
        return self._exchange(chunks[-1])

    @contextmanager
    def sign_cip36_confirm_async(
        self, testCase: CVoteTestCase
    ) -> Generator[None, None, None]:
        """APDU CIP36 Vote - CONFIRM step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_cvote_confirm(testCase)):
            yield

    def sign_msg(
        self, testCase, on_review: Optional[Callable[[], None]] = None
    ) -> tuple:
        """Sign a message, returning the unpacked response components.

        Args:
            testCase: SignMsgTestCase data
            on_review: Optional callback invoked while waiting for user confirmation

        Returns:
            Tuple of (signature: bytes, public_key: bytes, address_field: bytes)
        """
        response = self._exchange(self._cmd_builder.sign_msg_init(testCase))
        if response.status != StatusWord.SWO_SUCCESS:
            raise AssertionError(f"Init failed: {hex(response.status)}")

        chunk_apdus = self._cmd_builder.sign_msg_chunks(testCase)
        for chunk_apdu in chunk_apdus:
            response = self._exchange(chunk_apdu)
            if response.status != StatusWord.SWO_SUCCESS:
                raise AssertionError(f"Chunk failed: {hex(response.status)}")

        with self._sign_msg_confirm_async():
            if on_review is not None:
                on_review()

        confirm_response = self.get_async_response()
        if confirm_response is None:
            raise AssertionError("No response from confirm")
        if confirm_response.status != StatusWord.SWO_SUCCESS:
            raise AssertionError(f"Confirm failed: {hex(confirm_response.status)}")
        return unpack_sign_message_response(confirm_response.data)

    @contextmanager
    def _sign_msg_confirm_async(self) -> Generator[None, None, None]:
        """APDU Sign Message - CONFIRM step

        Returns:
            Generator
        """
        with self._exchange_async(self._cmd_builder.sign_msg_confirm()):
            yield
