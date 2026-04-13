# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

# Test file for Cardano transaction signing with simple chunked flow

import pytest
from ledgered.devices import Device
from ragger.backend import BackendInterface
from ragger.navigator import Navigator, NavInsID, NavIns
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.error import ExceptionRAPDU

from tests.application_client.status_words import StatusWord
from tests.application_client.command_builder import (
    gather_witness_paths,
    TxAuxiliaryDataCIP36,
)
from tests.application_client.command_sender import CommandSender
from tests.application_client.response_unpacker import unpack_sign_tx_witness_response
from tests.standalone.utils import (
    verify_signature,
    idTestFunc,
    review_approve,
    choice_approve,
    choice_reject,
    nano_navigate_until_text_relaxed,
    NavContext,
    assert_expected_deny_and_app_alive,
)
from tests.standalone.settings import SettingID, SettingValue, settings_set
from tests.standalone.input_files.signTx import (
    testsByron,
    testsMary,
    testsShelleyNoCertificates,
    testsShelleyWithCertificates,
    testsConwayWithCertificates,
    testsAllegra,
    testsAlonzoTrezorComparison,
    testsBabbageTrezorComparison,
    testsAlonzo,
    testsStreaming,
    testsBabbage,
    testsConwayWithoutCertificates,
    testsConwayVotingProcedures,
    testsMultidelegation,
    testsCatalystRegistration,
    testsCVoteRegistrationCIP36,
    BlindSigningMode,
    testsMultisig,
    poolRegistrationOwnerTestCases,
    poolRegistrationOperatorTestCases,
    transactionInitDenyTestCases,
    addressParamsDenyTestCases,
    certificateDenyTestCases,
    certificateStakingDenyTestCases,
    certificateStakePoolRetirementDenyTestCases,
    withdrawalDenyTestCases,
    witnessDenyTestCases,
    singleAccountDenyTestCases,
    collateralOutputDenyTestCases,
    testsInvalidTokenBundleOrdering,
    votingDenyTestCases,
    poolRegistrationOwnerDenyTestCases,
    stakePoolRegistrationPoolIdDenyTestCases,
    invalidCertificates,
    invalidPoolMetadataTestCases,
    invalidRelayTestCases,
    testsCVoteRegistrationDenies,
    SignTxTestCase,
    TxAuxiliaryDataType,
    ThirdPartyAddressParams,
    TransactionSigningMode,
    Witness,
)


def _reason_applies_to_device(device: Device, reason: str) -> tuple[bool, str]:
    if reason.startswith("nano:"):
        return device.is_nano, reason[len("nano:") :].strip()
    if reason.startswith("non_nano:"):
        return (not device.is_nano), reason[len("non_nano:") :].strip()
    if reason.startswith("all:"):
        return True, reason[len("all:") :].strip()
    return True, reason


def skip_in_ragger(device: Device, reasons: list[str | None]) -> None:
    for reason in reasons:
        if reason is not None:
            applies, message = _reason_applies_to_device(device, reason)
            if applies:
                pytest.skip(f"Unsuitable in ragger: {message}")


def _run_sign_tx_test(
    device: Device,
    backend: BackendInterface,
    navigator: Navigator,
    scenario_navigator: NavigateWithScenario,
    testCase: SignTxTestCase,
    expert_mode: bool,
) -> None:
    """Helper function to run a single sign_tx test iteration.

    Args:
        device: The Ledger device
        backend: The backend interface
        navigator: The navigator for UI interactions
        scenario_navigator: Scenario-based navigator
        testCase: The test case to run
        expert_mode: Whether expert mode is enabled for this run
    """
    mode_str = "expert" if expert_mode else "non_expert"
    print(f"\n{'=' * 60}")
    print(f"Running test in {mode_str} mode: {testCase.name}")
    print(f"{'=' * 60}")

    nav_ctx = NavContext(device, navigator, scenario_navigator)
    client = CommandSender(backend)
    assert testCase.tx is not None
    assert testCase.signingMode is not None
    if testCase.ragger_expect is None:
        pytest.fail(
            f"Missing ragger_expect for happy-path signTx fixture {testCase.name!r}"
        )
    tx = testCase.tx

    auxiliary_data = testCase.tx.auxiliaryData
    is_cip36_auxiliary_review = (
        auxiliary_data is not None
        and auxiliary_data.type == TxAuxiliaryDataType.CIP36_REGISTRATION
    )

    def review_cvote() -> None:
        # CVote auxiliary data review (if present)
        if not is_cip36_auxiliary_review:
            return

        test_name = f"{testCase.name}-{mode_str}/cvote_review"
        if not device.is_nano:
            if testCase.expected_aux_warnings:
                detail_navigation: list[NavIns | NavInsID] = [NavInsID.RIGHT_HEADER_TAP]
                for warning_index in range(min(len(testCase.expected_aux_warnings), 3)):
                    detail_navigation += [
                        NavIns(NavInsID.CHOICE_CHOOSE, (warning_index + 1,)),
                        NavInsID.LEFT_HEADER_TAP,
                    ]
                if len(testCase.expected_aux_warnings) > 3:
                    detail_navigation += [
                        NavIns(NavInsID.CHOICE_CHOOSE, (4,)),
                        NavInsID.LEFT_HEADER_TAP,
                    ]
                detail_navigation += [NavInsID.LEFT_HEADER_TAP]

                navigator.navigate_and_compare(
                    scenario_navigator.screenshot_path,
                    f"{test_name}/warning/details",
                    detail_navigation,
                )
                navigator.navigate_and_compare(
                    scenario_navigator.screenshot_path,
                    f"{test_name}/warning",
                    [NavInsID.USE_CASE_CHOICE_REJECT],
                    screen_change_before_first_instruction=False,
                    screen_change_after_last_instruction=False,
                )

            navigator.navigate_until_text_and_compare(
                navigate_instruction=NavInsID.USE_CASE_REVIEW_NEXT,
                validation_instructions=[],
                text=r"^Hold to sign$",
                path=scenario_navigator.screenshot_path,
                test_case_name=test_name,
                screen_change_before_first_instruction=True,
            )
            navigator.navigate(
                [NavInsID.USE_CASE_REVIEW_CONFIRM],
                screen_change_before_first_instruction=False,
                screen_change_after_last_instruction=False,
            )
            return

        review_approve(
            nav_ctx,
            test_name=test_name,
            target_text=r"^Confirm vote"
            if not testCase.expected_aux_warnings
            else r"^Reject operation$",
            warnings=testCase.expected_aux_warnings,
            nano_review_instructions=(
                [NavInsID.LEFT_CLICK, NavInsID.BOTH_CLICK]
                if testCase.expected_aux_warnings
                else None
            ),
        )

    def review_tx() -> None:
        # Main transaction review
        test_name = f"{testCase.name}-{mode_str}/review"
        resume_tx_review_from_current_screen = False
        effective_tx_review_streaming = testCase.tx_streaming
        if testCase.blind_signing_mode == BlindSigningMode.PROMPT_REVIEW_FULL:
            choice_approve(
                nav_ctx,
                test_name=f"{test_name}/blind_signing",
                confirm_text=r"^Show details$",
                do_comparison=False,
                dismiss_status=False,
            )
            resume_tx_review_from_current_screen = True
        elif testCase.blind_signing_mode == BlindSigningMode.PROMPT_REVIEW_HASH:
            choice_reject(
                nav_ctx,
                test_name=f"{test_name}/blind_signing",
                reject_text=r"^View hash only$",
                do_comparison=False,
                dismiss_status=False,
            )
            effective_tx_review_streaming = False
            resume_tx_review_from_current_screen = True
        if effective_tx_review_streaming:
            if device.is_nano:
                nano_navigate_until_text_relaxed(
                    backend=backend,
                    navigator=navigator,
                    navigate_instruction=NavInsID.RIGHT_CLICK,
                    validation_instructions=[NavInsID.BOTH_CLICK],
                    text=r"^Sign transaction$",
                    screen_change_before_first_instruction=not resume_tx_review_from_current_screen,
                )
            else:
                # Streaming tx review: navigate through intermediate chunks without snapshots,
                # then capture only the final "Sign transaction" screen.
                navigator.navigate_until_text(
                    navigate_instruction=NavInsID.USE_CASE_REVIEW_NEXT,
                    validation_instructions=[NavInsID.USE_CASE_REVIEW_CONFIRM],
                    text="Sign transaction",
                    screen_change_before_first_instruction=not resume_tx_review_from_current_screen,
                )
        elif len(testCase.expected_warnings) > 0:
            review_approve(
                nav_ctx,
                test_name=test_name,
                warnings=testCase.expected_warnings,
                target_text="Sign transaction",
            )
        else:
            review_approve(
                nav_ctx,
                test_name=test_name,
                target_text="Sign transaction",
                screen_change_before_first_instruction=not resume_tx_review_from_current_screen,
            )

    def _is_cip36_aux_review_streaming() -> bool:
        if not is_cip36_auxiliary_review or auxiliary_data is None:
            return False

        assert isinstance(auxiliary_data.params, TxAuxiliaryDataCIP36)
        auxiliary_params = auxiliary_data.params
        pair_count = 1  # "Delegations"
        pair_count += 1  # "Staking key"
        pair_count += 1  # "Rewards go to"
        pair_count += 1  # "Nonce"
        if auxiliary_params.votingPurpose is not None:
            pair_count += 1
        if auxiliary_params.voteKey is not None:
            pair_count += 1
            if isinstance(
                auxiliary_params.voteKey, str
            ) and auxiliary_params.voteKey.startswith("m/"):
                vote_key_path = auxiliary_params.voteKey.replace("'", "").split("/")
                try:
                    account_index = (
                        int(vote_key_path[3]) if len(vote_key_path) > 3 else 0
                    )
                except ValueError:
                    account_index = 0
                if account_index > 100:
                    pair_count += 1

        pair_count += 4 * len(auxiliary_params.delegations)
        max_ui_pairs = 127 if device.is_nano else 255
        return pair_count > max_ui_pairs

    def review_advance(nb_steps: int = 1) -> None:
        if device.is_nano:
            if is_cip36_auxiliary_review:
                if not _is_cip36_aux_review_streaming():
                    return
                if nb_steps == 2:
                    nano_navigate_until_text_relaxed(
                        backend=backend,
                        navigator=navigator,
                        navigate_instruction=NavInsID.RIGHT_CLICK,
                        validation_instructions=[NavInsID.RIGHT_CLICK],
                        text=r"^Delegations$",
                        screen_change_before_first_instruction=False,
                    )
                else:
                    navigator.navigate(
                        [NavInsID.RIGHT_CLICK] * 4,
                        screen_change_before_first_instruction=False,
                        screen_change_after_last_instruction=False,
                    )
                return
            # Nano review pages can split long values across extra screens.
            # Use a Nano-specific advancement strategy.
            # `nb_steps == 2` is used for AUX init (registration + first delegation).
            # The registration part itself spans multiple Nano screens.
            initial_aux_init_advance_steps = 6 if expert_mode else 5
            steps_to_advance = initial_aux_init_advance_steps if nb_steps == 2 else 4
            navigator.navigate(
                [NavInsID.RIGHT_CLICK] * steps_to_advance,
                screen_change_before_first_instruction=False,
                screen_change_after_last_instruction=False,
            )
        else:
            navigator.navigate(
                [NavInsID.USE_CASE_REVIEW_NEXT] * nb_steps,
                screen_change_before_first_instruction=False,
                screen_change_after_last_instruction=False,
            )

    tx_hash, cip36_aux_data = client.sign_tx(
        tx=tx,
        signing_mode=testCase.signingMode,
        additional_witness_paths=testCase.additionalWitnessPaths,
        options=testCase.options,
        on_review=review_tx,
        on_cvote_review=review_cvote,
        on_advance=review_advance,
    )
    if cip36_aux_data is not None:
        aux_data_hash, registration_signature = cip36_aux_data
        print(f"CIP36 aux data hash: {aux_data_hash.hex()}")
        print(f"CIP36 registration signature: {registration_signature.hex()}")

    def _is_ordinary_witness_path(witness_path: str) -> bool:
        path_elements = witness_path.replace("'", "").split("/")
        if len(path_elements) < 2:
            return False
        try:
            purpose = int(path_elements[1])
        except ValueError:
            return False
        return purpose in (44, 1852)

    def _is_mint_witness_path(witness_path: str) -> bool:
        path_elements = witness_path.replace("'", "").split("/")
        if len(path_elements) < 2:
            return False
        try:
            purpose = int(path_elements[1])
        except ValueError:
            return False
        return purpose == 1855

    def _is_unusual_witness_path_for_navigation(witness_path: str) -> bool:
        # Keep this aligned with Ledger-side "reasonable path" behavior for ordinary witnesses.
        # We need this to decide whether witness confirmation UI is expected.
        path_elements = witness_path.replace("'", "").split("/")
        if len(path_elements) < 5:
            return False
        try:
            purpose = int(path_elements[1])
            account = int(path_elements[3])
            chain = int(path_elements[4]) if len(path_elements) > 5 else 0
        except ValueError:
            return False

        if purpose > 1852:
            return True
        if account > 100:
            return True
        if chain > 2:
            return True
        return False

    # Step 4: Get witness signatures
    # After user approval, request signatures for all witness paths
    witness_paths = gather_witness_paths(
        tx, testCase.signingMode, testCase.additionalWitnessPaths or []
    )
    print(f"Witness paths: {witness_paths}")

    collected_witnesses: list[Witness] = []
    for path_idx, path in enumerate(witness_paths):
        # Pool registration witnesses (owner/operator) always need confirmation.
        pool_or_plutus_modes = (
            TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
            TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
            TransactionSigningMode.PLUTUS_TRANSACTION,
        )
        witness_has_non_hidden_review = (
            _is_unusual_witness_path_for_navigation(path)
            or testCase.signingMode in pool_or_plutus_modes
            or (
                len(tx.outputs) > 0
                and not isinstance(
                    tx.outputs[0].destination.params, ThirdPartyAddressParams
                )
                and auxiliary_data is not None
                and auxiliary_data.type != TxAuxiliaryDataType.CIP36_REGISTRATION
            )
        )
        should_confirm_witness = (
            witness_has_non_hidden_review
            or _is_mint_witness_path(path)
            or (expert_mode and _is_ordinary_witness_path(path))
        )

        # Each witness requires explicit confirmation on the device
        with client.sign_tx_witness_async(path):
            if should_confirm_witness:
                test_name = f"{testCase.name}-{mode_str}/witness_{path_idx}"
                choice_approve(
                    nav_ctx,
                    test_name=test_name,
                    confirm_text=r"^Confirm$",
                )
            else:
                pass

        response = client.get_async_response()
        assert response is not None, f"No response for witness {path_idx}: {path}"
        assert response.status == StatusWord.SWO_SUCCESS, (
            f"Witness failed for {path}: {hex(response.status)}"
        )

        signature = unpack_sign_tx_witness_response(response.data)
        print(
            f"Witness signature for {path} ({len(signature)} bytes): {signature.hex()}"
        )
        verify_signature(path, signature, tx_hash)
        collected_witnesses.append(
            Witness(path=path, witnessSignatureHex=signature.hex())
        )

    _check_ragger_expect_sign_tx(testCase, tx_hash, collected_witnesses)


def _check_ragger_expect_sign_tx(
    testCase: SignTxTestCase,
    tx_hash: bytes,
    collected_witnesses: list[Witness],
) -> None:
    assert testCase.ragger_expect is not None, (
        f"Missing ragger_expect for happy-path signTx fixture {testCase.name!r}"
    )
    assert testCase.ragger_expect.txHashHex is not None, (
        f"Missing ragger_expect.txHashHex for happy-path signTx fixture {testCase.name!r}"
    )
    assert testCase.ragger_expect.witnesses is not None, (
        f"Missing ragger_expect.witnesses for happy-path signTx fixture {testCase.name!r}"
    )

    assert tx_hash.hex() == testCase.ragger_expect.txHashHex, (
        f"Tx hash mismatch for {testCase.name!r}"
    )

    assert len(collected_witnesses) == len(testCase.ragger_expect.witnesses), (
        f"Witness count mismatch for {testCase.name!r}: "
        f"got {len(collected_witnesses)}, expected {len(testCase.ragger_expect.witnesses)}"
    )
    for idx, (actual, expected) in enumerate(
        zip(collected_witnesses, testCase.ragger_expect.witnesses)
    ):
        assert actual.witnessSignatureHex == expected.witnessSignatureHex, (
            f"Witness[{idx}] signature mismatch for {testCase.name!r} path={actual.path!r}"
        )


@pytest.mark.parametrize("expert_mode", [False, True], ids=["non_expert", "expert"])
@pytest.mark.parametrize(
    "testCase",
    testsByron
    + testsMary
    + testsShelleyNoCertificates
    + testsShelleyWithCertificates
    + testsAllegra
    + testsAlonzoTrezorComparison
    + testsBabbageTrezorComparison
    + testsAlonzo
    + testsStreaming
    + testsBabbage
    + testsConwayWithCertificates
    + testsConwayWithoutCertificates
    + testsConwayVotingProcedures
    + testsMultidelegation
    + testsCatalystRegistration
    + testsCVoteRegistrationCIP36
    + testsMultisig
    + poolRegistrationOwnerTestCases
    + poolRegistrationOperatorTestCases,
    ids=idTestFunc,
)
def test_sign_tx(
    device: Device,
    backend: BackendInterface,
    navigator: Navigator,
    scenario_navigator: NavigateWithScenario,
    testCase: SignTxTestCase,
    expert_mode: bool,
) -> None:
    """Test transaction signing under a specific expert mode setting.

    Each run performs:
    1. Toggle expert mode via settings menu navigation (if needed)
    2. Send init APDU with transaction description
    3. Send transaction data in unpacked format
    4. User approves transaction
    5. Request witness signature
    """
    skip_in_ragger(
        device,
        [
            testCase.unsuitable_in_ragger_reason,
        ],
    )

    # Force the requested expert-mode state via the on-device settings menu.
    settings_set(
        device,
        navigator,
        {
            SettingID.EXPERT_MODE: SettingValue.ENABLED
            if expert_mode
            else SettingValue.DISABLED,
            SettingID.SILENT_PUBKEY_EXPORT: SettingValue.ENABLED,
            SettingID.BLIND_SIGNING: SettingValue.ENABLED
            if testCase.blind_signing_mode != BlindSigningMode.DISABLED
            else SettingValue.DISABLED,
        },
        backend=backend,
    )

    try:
        _run_sign_tx_test(
            device,
            backend,
            navigator,
            scenario_navigator,
            testCase,
            expert_mode=expert_mode,
        )
    except Exception as e:
        mode_label = "EXPERT MODE" if expert_mode else "NON-EXPERT MODE"
        raise AssertionError(f"Test FAILED in {mode_label}: {testCase.name}") from e


# Collect all deny test cases
all_deny_test_cases = (
    transactionInitDenyTestCases
    + addressParamsDenyTestCases
    + certificateDenyTestCases
    + certificateStakingDenyTestCases
    + certificateStakePoolRetirementDenyTestCases
    + withdrawalDenyTestCases
    + witnessDenyTestCases
    + singleAccountDenyTestCases
    + collateralOutputDenyTestCases
    + testsInvalidTokenBundleOrdering
    + votingDenyTestCases
    + poolRegistrationOwnerDenyTestCases
    + stakePoolRegistrationPoolIdDenyTestCases
    + invalidCertificates
    + invalidPoolMetadataTestCases
    + invalidRelayTestCases
    + testsCVoteRegistrationDenies
)


@pytest.mark.parametrize("testCase", all_deny_test_cases, ids=idTestFunc)
def test_sign_tx_deny(
    backend: BackendInterface,
    device: Device,
    navigator: Navigator,
    scenario_navigator: NavigateWithScenario,
    testCase: SignTxTestCase,
) -> None:
    """Test that invalid transaction parameters are correctly denied."""

    skip_in_ragger(
        device,
        [
            testCase.unsuitable_in_ragger_reason,
        ],
    )

    nav_ctx = NavContext(device, navigator, scenario_navigator)
    client = CommandSender(backend)
    assert testCase.tx is not None
    assert testCase.signingMode is not None
    deny_tx = testCase.tx
    deny_signing_mode = testCase.signingMode

    def _requires_warning_navigation() -> bool:
        if len(testCase.expected_warnings) > 0:
            return True

        if deny_signing_mode == TransactionSigningMode.PLUTUS_TRANSACTION:
            return True

        for certificate in deny_tx.certificates:
            cert_params = getattr(certificate, "params", None)
            if cert_params is None:
                continue
            if hasattr(cert_params, "poolOwners") and len(cert_params.poolOwners) == 0:
                return True
            if hasattr(cert_params, "relays") and len(cert_params.relays) == 0:
                return True
        return False

    def review_tx() -> None:
        if testCase.deny_before_review:
            return

        if _requires_warning_navigation():
            review_approve(
                nav_ctx,
                test_name=f"{testCase.name}-deny/review",
                warnings=testCase.expected_warnings,
                has_warning_screen=True,
                do_comparison=False,
                target_text="Sign transaction",
            )
        elif device.is_nano:
            navigator.navigate_until_text(
                navigate_instruction=NavInsID.RIGHT_CLICK,
                validation_instructions=[NavInsID.BOTH_CLICK],
                text=r"^Sign transaction$",
                screen_change_before_first_instruction=True,
            )
        else:
            review_approve(
                nav_ctx,
                test_name=f"{testCase.name}-deny/review",
                do_comparison=False,
            )

    # Phase 1: try to observe the expected deny during init/chunk/review.
    try:
        client.sign_tx(
            tx=deny_tx,
            signing_mode=deny_signing_mode,
            additional_witness_paths=testCase.additionalWitnessPaths,
            options=testCase.options,
            on_review=review_tx,
        )
    except ExceptionRAPDU as err:
        assert_expected_deny_and_app_alive(backend, err, testCase.expected_swo)
        return

    # Phase 2: tx body passed; expected denial must happen in witness phase.
    witness_paths = gather_witness_paths(
        deny_tx,
        deny_signing_mode,
        testCase.additionalWitnessPaths or [],
    )
    if len(witness_paths) == 0:
        raise AssertionError(
            "Transaction unexpectedly succeeded but no witness paths were found"
        )

    witness_paths_to_try = (
        [testCase.additionalWitnessPaths[-1]]
        if len(testCase.additionalWitnessPaths) > 0
        else list(reversed(witness_paths))
    )

    deny_observed = False
    for witness_path in witness_paths_to_try:
        try:
            client.sign_tx_witness(witness_path)
        except ExceptionRAPDU as err:
            if err.status == testCase.expected_swo:
                assert_expected_deny_and_app_alive(backend, err, testCase.expected_swo)
                deny_observed = True
                break
            raise

        # Witness succeeded, continue searching for the deny-driving path.
        # Successful witnesses here are expected to be POLICY_HIDE paths.
        continue

    assert deny_observed, "Expected witness-level DENY was not observed"
