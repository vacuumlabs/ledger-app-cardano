cmake_minimum_required(VERSION 3.10)

if(${CMAKE_VERSION} VERSION_LESS 3.10)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(unit_tests
        VERSION 0.1
	      DESCRIPTION "Unit tests for Ledger Nano application"
        LANGUAGES C)


# guard against bad build-type strings
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

include(CTest)
ENABLE_TESTING()

# specify C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -g -O0 --coverage")

set(GCC_COVERAGE_LINK_FLAGS "--coverage -lgcov")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()

add_compile_definitions(DEBUG)
add_compile_definitions(TARGET_NANOX)

# IMPORTANT: mock_includes MUST come first so our SDK mocks override Ledger SDK headers
# (We use real headers from ../../src for app-specific code like utils.h, assert.h, etc.)
include_directories(mock_includes)
include_directories(.)
include_directories(libs)
include_directories(../../src)
include_directories(../../src/bech32)
include_directories(../../src/utils)
include_directories(../../src/memory)
include_directories(../../src/addressUtils)
include_directories(../../src/crypto)
include_directories(../../src/deriveNativeScriptHash)
include_directories(../../src/transaction)
include_directories(../../src/ui)
include_directories(../../src/opcert)
include_directories(../../src/parsers)
include_directories(../../src/securityPolicy)
include_directories(../../src/messageSigning)
include_directories(../../src/apdu)
include_directories(../../src/txHashBuilder)
include_directories(../../src/cardano_tokens)
include_directories(../../src/keyDerivation)
include_directories(../../src/handler)
include_directories(../../src/cvote)
include_directories(../../src/tokenRegistry)
include_directories(../../src/swap)
include_directories($ENV{BOLOS_SDK}/lib_standard_app)
include_directories($ENV{BOLOS_SDK}/include)
include_directories($ENV{BOLOS_SDK}/lib_alloc)
include_directories($ENV{BOLOS_SDK}/lib_lists)
include_directories($ENV{BOLOS_SDK}/lib_cxng/include)
include_directories($ENV{BOLOS_SDK}/lib_nbgl/include)
include_directories(test_utils)
include_directories(generated/sign_tx)
include_directories(generated/sign_msg)
include_directories(generated/pubkey)
include_directories(generated/derive_address)
include_directories(generated/native_script)
include_directories(generated/cvote)
include_directories(generated/opcert)

set(UNIT_TEST_MEM_UTILS_STUB mock_sources/mem_utils_stub.c)
set(UNIT_TEST_MEM_UTILS_REAL_ALLOC
    $ENV{BOLOS_SDK}/lib_alloc/app_mem_utils.c
    $ENV{BOLOS_SDK}/lib_alloc/mem_alloc.c
    mock_sources/os_longjmp_stub.c)

# Helper: add a unit test executable, link it, and register it with CTest.
# Usage: cardano_unit_test(<name> SOURCES <src>... LIBS <lib>...)
function(cardano_unit_test name)
    cmake_parse_arguments(ARG "" "" "SOURCES;LIBS" ${ARGN})
    add_executable(${name} ${ARG_SOURCES})
    target_link_libraries(${name} PUBLIC cmocka gcov ${ARG_LIBS})
    add_test(${name} ${name})
endfunction()

add_compile_definitions(HAVE_CRC)
add_compile_definitions(HAVE_PRINTF)
add_compile_definitions(HAVE_SNPRINTF_FORMAT_U)
add_compile_definitions(HAVE_SNPRINTF_FORMAT_LL)
# Prevent os.h from defining PRINTF as empty macro
add_compile_definitions(PRINTF=mcu_usb_printf)
add_compile_definitions(APPNAME=\"Cardano\")
add_compile_definitions(APPVERSION=\"8.0.0\")
add_compile_definitions(MAJOR_VERSION=8)
add_compile_definitions(MINOR_VERSION=0)
add_compile_definitions(PATCH_VERSION=0)

# SDK libraries
add_library(base58 SHARED $ENV{BOLOS_SDK}/lib_standard_app/base58.c)
add_library(bip32 SHARED $ENV{BOLOS_SDK}/lib_standard_app/bip32.c)
add_library(buffer SHARED $ENV{BOLOS_SDK}/lib_standard_app/buffer.c)
target_link_libraries(buffer PUBLIC varint bip32 read write)
add_library(read SHARED $ENV{BOLOS_SDK}/lib_standard_app/read.c)
add_library(write SHARED $ENV{BOLOS_SDK}/lib_standard_app/write.c)
add_library(format SHARED $ENV{BOLOS_SDK}/lib_standard_app/format.c)
add_library(varint SHARED $ENV{BOLOS_SDK}/lib_standard_app/varint.c)
target_link_libraries(varint PUBLIC write)
add_library(apdu_parser SHARED $ENV{BOLOS_SDK}/lib_standard_app/parser.c)

# App-specific libraries (testing the REAL source files!)
# The mock_includes/ directory is prioritized so our SDK mocks override Ledger SDK headers
add_library(hex_utils SHARED test_utils/hexUtils.c)
target_link_libraries(hex_utils PUBLIC c)
add_library(bech32_lib SHARED ../../src/bech32/bech32.c)
target_link_libraries(bech32_lib PUBLIC c)
add_library(text_utils SHARED ../../src/utils/textUtils.c ../../src/utils/ipUtils.c)
target_link_libraries(text_utils PUBLIC c format)
add_library(bip44_real SHARED ../../src/addressUtils/bip44.c)
target_link_libraries(bip44_real PUBLIC c read write buffer varint)
add_library(cbor_lib SHARED ../../src/utils/cbor.c ../../src/utils/cbor_canonical.c)
target_link_libraries(cbor_lib PUBLIC c m read)
add_library(cardano_buffer_lib SHARED ../../src/utils/cardano_buffer.c)
target_link_libraries(cardano_buffer_lib PUBLIC c cbor_lib buffer write)
add_library(parsers_lib SHARED ../../src/parsers/cardano_parsers.c)
target_link_libraries(parsers_lib PUBLIC c buffer read write varint bip32 text_utils bip44_real)
add_library(crypto_mocks_lib SHARED
    mock_crypto/crypto_mocks.c
)
target_link_libraries(crypto_mocks_lib PUBLIC c)
add_library(mock_printf STATIC
    $ENV{BOLOS_SDK}/src/os_printf.c
    mock_sources/os_printf_sink.c
)
target_link_libraries(mock_printf PUBLIC c)
add_library(cx_crc_support SHARED
    libs/crc32_mock.c
)
target_link_libraries(cx_crc_support PUBLIC c)

set(SIGN_TX_COMMON_SOURCES
    mock_sources/mock_globals.c
    $ENV{BOLOS_SDK}/lib_lists/lists.c
    ../../src/utils/mem.c
    ../../src/handler/sign_tx.c
    ../../src/handler/sign_tx_aux_data.c
    ../../src/handler/sign_cvote.c
    ../../src/cvote/cvote_parser.c
    ../../src/cvote/cvote_hash.c
    ../../src/cvote/vote_cast_hash_builder.c
    ../../src/cvote/aux_data_hash_builder.c
    ../../src/transaction/tx_parse.c
    ../../src/transaction/tx_processing.c
    ../../src/transaction/tx_processing_outputs.c
    ../../src/transaction/tx_processing_certificates.c
    ../../src/transaction/tx_ui_render.c
    ../../src/transaction/tx_ui_render_certificates.c
    ../../src/transaction/tx_ui_render_outputs.c
    ../../src/transaction/tx_parse_certificates.c
    ../../src/transaction/tx_parse_outputs.c
    ../../src/transaction/tx_utils.c
    ../../src/parsers/cardano_parsers.c
    ../../src/securityPolicy/securityPolicy.c
    ../../src/securityPolicy/securityPolicy_privkey.c
    ../../src/messageSigning/messageSigning.c
    ../../src/keyDerivation/keyDerivation.c
    ../../src/cardano_tokens/cardano_tokens.c
    ../../src/addressUtils/addressUtilsShelley.c
    ../../src/addressUtils/addressUtilsByron.c
    ../../src/transaction/tx_hash_builder.c
    ../../src/ui/ui_address_fields.c
    ../../src/ui/ui_utils.c
    ../../src/ui/ui_warnings.c
    ../../src/ui/ui_formatters.c
    ../../src/app_context.c
    ${UNIT_TEST_MEM_UTILS_STUB}
    mock_sources/glyphs_mock.c
    mock_sources/hex_stub.c
    mock_sources/os_lib_end_stub.c
    test_utils/io_capture.c
    # Real UI display code - calls NBGL functions mocked in nbgl_mock.c
    ../../src/ui/ui_display_tx.c
    ../../src/ui/ui_display_witness.c
    ../../src/ui/ui_cvote.c
    ../../src/ui/ui_display_cvote_aux_data.c
    mock_sources/nbgl_mock.c
)
set(SIGN_TX_COMMON_LIBS
    text_utils
    hex_utils
    base58
    bech32_lib
    bip44_real
    cardano_buffer_lib
    cbor_lib
    blake2b_lib
    sha3_lib
    hash_mocks_lib
    crypto_mocks_lib
    buffer
    write
    read
    varint
    bip32
    cx_crc_support
    mock_printf
)
add_library(cardano_sign_tx_core STATIC ${SIGN_TX_COMMON_SOURCES})
target_link_libraries(cardano_sign_tx_core PUBLIC ${SIGN_TX_COMMON_LIBS})
target_compile_definitions(cardano_sign_tx_core PRIVATE TRACE_TX_HASH_BUILDER)

set(SIGN_TX_COMMON_SOURCES_SWAP
    ${SIGN_TX_COMMON_SOURCES}
    mock_sources/swap_test_stubs.c
)
add_library(cardano_sign_tx_core_swap STATIC ${SIGN_TX_COMMON_SOURCES_SWAP})
target_link_libraries(cardano_sign_tx_core_swap PUBLIC ${SIGN_TX_COMMON_LIBS})
target_compile_definitions(cardano_sign_tx_core_swap PRIVATE TRACE_TX_HASH_BUILDER HAVE_SWAP)

set(SIGN_TX_COMMON_SOURCES_REAL_ALLOC ${SIGN_TX_COMMON_SOURCES})
list(REMOVE_ITEM SIGN_TX_COMMON_SOURCES_REAL_ALLOC ${UNIT_TEST_MEM_UTILS_STUB})
list(APPEND SIGN_TX_COMMON_SOURCES_REAL_ALLOC ${UNIT_TEST_MEM_UTILS_REAL_ALLOC})
add_library(cardano_sign_tx_core_real_alloc STATIC ${SIGN_TX_COMMON_SOURCES_REAL_ALLOC})
target_link_libraries(cardano_sign_tx_core_real_alloc PUBLIC ${SIGN_TX_COMMON_LIBS})
target_compile_definitions(cardano_sign_tx_core_real_alloc PRIVATE TRACE_TX_HASH_BUILDER)

# Crypto reference implementations
add_library(blake2b_lib SHARED libs/blake2b.c)
target_link_libraries(blake2b_lib PUBLIC c)
add_library(sha3_lib SHARED libs/sha3-256.c)
target_link_libraries(sha3_lib PUBLIC c)
add_library(hash_mocks_lib SHARED libs/hash_mocks.c)
target_link_libraries(hash_mocks_lib PUBLIC c)

# Link hash_mocks to crypto libs
target_link_libraries(hash_mocks_lib PUBLIC blake2b_lib sha3_lib)


# Early simple tests
cardano_unit_test(test_hex_utils
    SOURCES test_hex_utils.c
    LIBS hex_utils mock_printf)

cardano_unit_test(test_bech32
    SOURCES test_bech32.c
    LIBS bech32_lib hex_utils mock_printf)

cardano_unit_test(test_text_utils
    SOURCES
        test_text_utils.c
        ../../src/ui/ui_formatters.c
        ../../src/cardano_tokens/cardano_tokens.c
        ../../src/utils/textUtils.c
        ../../src/utils/ipUtils.c
        mock_sources/hex_stub.c
    LIBS
        bech32_lib
        hex_utils
        hash_mocks_lib
        blake2b_lib
        sha3_lib
        cardano_buffer_lib
        format
        mock_printf)

cardano_unit_test(test_ui_formatters
    SOURCES
        test_ui_formatters.c
        ../../src/ui/ui_formatters.c
        ../../src/cardano_tokens/cardano_tokens.c
        ../../src/utils/textUtils.c
        ../../src/utils/ipUtils.c
        mock_sources/hex_stub.c
    LIBS
        bech32_lib
        hex_utils
        hash_mocks_lib
        blake2b_lib
        sha3_lib
        cardano_buffer_lib
        format
        mock_printf)

cardano_unit_test(test_cardano_tokens
    SOURCES
        test_cardano_tokens.c
        ../../src/cardano_tokens/cardano_tokens.c
        ../../src/ui/ui_formatters.c
        ../../src/utils/textUtils.c
        ../../src/utils/ipUtils.c
        mock_sources/hex_stub.c
    LIBS
        bech32_lib
        hex_utils
        hash_mocks_lib
        blake2b_lib
        sha3_lib
        cardano_buffer_lib
        format
        mock_printf)

cardano_unit_test(test_bip44
    SOURCES test_bip44.c
    LIBS bip44_real mock_printf)

cardano_unit_test(test_cbor
    SOURCES test_cbor.c
    LIBS cbor_lib hex_utils read write c mock_printf)

cardano_unit_test(test_cardano_buffer
    SOURCES test_cardano_buffer.c
    LIBS cardano_buffer_lib buffer write varint bip32 parsers_lib mock_printf)

cardano_unit_test(test_ip_utils
    SOURCES test_ip_utils.c ../../src/utils/ipUtils.c
    LIBS mock_printf)

cardano_unit_test(test_hash
    SOURCES test_hash.c
    LIBS hex_utils blake2b_lib sha3_lib hash_mocks_lib mock_printf)

cardano_unit_test(test_address_utils_byron
    SOURCES
        test_address_utils_byron.c
        ../../src/addressUtils/addressUtilsByron.c
        ../../src/keyDerivation/keyDerivation.c
        ../../src/securityPolicy/securityPolicy_privkey.c
    LIBS
        crypto_mocks_lib
        bip44_real
        hex_utils
        hash_mocks_lib
        blake2b_lib
        sha3_lib
        cardano_buffer_lib
        cbor_lib
        buffer
        write
        read
        varint
        bip32
        cx_crc_support
        mock_printf)

cardano_unit_test(test_address_utils_shelley
    SOURCES
        test_address_utils_shelley.c
        ../../src/addressUtils/addressUtilsShelley.c
        ../../src/addressUtils/addressUtilsByron.c
        ../../src/keyDerivation/keyDerivation.c
        ../../src/securityPolicy/securityPolicy_privkey.c
    LIBS
        crypto_mocks_lib
        base58
        bech32_lib
        bip44_real
        hex_utils
        hash_mocks_lib
        blake2b_lib
        sha3_lib
        cardano_buffer_lib
        parsers_lib
        cbor_lib
        buffer
        write
        read
        varint
        bip32
        cx_crc_support
        mock_printf)

cardano_unit_test(test_key_derivation
    SOURCES
        test_key_derivation.c
        ../../src/keyDerivation/keyDerivation.c
        ../../src/securityPolicy/securityPolicy_privkey.c
    LIBS crypto_mocks_lib bip44_real hex_utils write hash_mocks_lib mock_printf)

cardano_unit_test(test_crypto
    SOURCES
        test_crypto.c
        ../../src/crypto/crypto.c
    LIBS mock_printf)

cardano_unit_test(test_security_policy_privkey
    SOURCES
        test_security_policy_privkey.c
        ../../src/securityPolicy/securityPolicy_privkey.c
    LIBS bip44_real mock_printf)

cardano_unit_test(test_message_signing
    SOURCES
        test_message_signing.c
        ../../src/messageSigning/messageSigning.c
        ../../src/keyDerivation/keyDerivation.c
        ../../src/securityPolicy/securityPolicy_privkey.c
    LIBS crypto_mocks_lib bip44_real hash_mocks_lib mock_printf)

cardano_unit_test(test_cvote
    SOURCES generated/cvote/test_cvote.c
    LIBS cardano_sign_tx_core mock_printf)

cardano_unit_test(test_sign_msg
    SOURCES generated/sign_msg/test_sign_msg.c
    LIBS cardano_sign_msg_core mock_printf)

cardano_unit_test(test_sign_msg_deny_tests
    SOURCES generated/sign_msg/test_sign_msg_deny_tests.c
    LIBS cardano_sign_msg_core mock_printf)

cardano_unit_test(test_aux_data_hash_builder
    SOURCES
        test_aux_data_hash_builder.c
        ../../src/cvote/aux_data_hash_builder.c
    LIBS
        hex_utils
        cbor_lib
        hash_mocks_lib
        blake2b_lib
        sha3_lib
        read
        write
        mock_printf)

cardano_unit_test(test_tx_hash_builder
    SOURCES
        test_tx_hash_builder.c
        ../../src/transaction/tx_hash_builder.c
    LIBS
        hash_mocks_lib
        blake2b_lib
        sha3_lib
        hex_utils
        cbor_lib
        cardano_buffer_lib
        buffer
        write
        read
        varint
        bip32
        mock_printf)

cardano_unit_test(test_ui_utils
    SOURCES
        test_ui_utils.c
        ../../src/ui/ui_utils.c
        ../../src/utils/mem.c
        ${UNIT_TEST_MEM_UTILS_STUB}
    LIBS mock_printf)

cardano_unit_test(test_ui_warnings
    SOURCES test_ui_warnings.c
    LIBS cardano_sign_tx_core mock_printf)

# Mary era tests (multiasset/tokens)
cardano_unit_test(test_sign_tx_mary
    SOURCES generated/sign_tx/test_sign_tx_mary.c
    LIBS cardano_sign_tx_core)

# Keep test_sign_tx_shelley as manual 3-line (has commented compile_definitions):
add_executable(test_sign_tx_shelley generated/sign_tx/test_sign_tx_shelley.c)
target_link_libraries(test_sign_tx_shelley PUBLIC cmocka gcov cardano_sign_tx_core)
#target_compile_definitions(test_sign_tx_shelley PRIVATE TRACE_TX_HASH_BUILDER)
add_test(test_sign_tx_shelley test_sign_tx_shelley)

cardano_unit_test(test_sign_tx_byron
    SOURCES generated/sign_tx/test_sign_tx_byron.c
    LIBS cardano_sign_tx_core)

# Shelley era tests with certificates
cardano_unit_test(test_sign_tx_shelley_certificates
    SOURCES generated/sign_tx/test_sign_tx_shelley_certificates.c
    LIBS cardano_sign_tx_core)

# Allegra era tests (validity intervals)
cardano_unit_test(test_sign_tx_allegra
    SOURCES generated/sign_tx/test_sign_tx_allegra.c
    LIBS cardano_sign_tx_core)

# Alonzo era tests (Plutus scripts)
cardano_unit_test(test_sign_tx_alonzo
    SOURCES generated/sign_tx/test_sign_tx_alonzo.c
    LIBS cardano_sign_tx_core)
cardano_unit_test(test_sign_tx_streaming
    SOURCES generated/sign_tx/test_sign_tx_streaming.c
    LIBS cardano_sign_tx_core)
cardano_unit_test(test_sign_tx_alonzo_catalyst
    SOURCES generated/sign_tx/test_sign_tx_alonzo_catalyst.c
    LIBS cardano_sign_tx_core)
cardano_unit_test(test_sign_tx_alonzo_cip36
    SOURCES generated/sign_tx/test_sign_tx_alonzo_cip36.c
    LIBS cardano_sign_tx_core)

# Babbage era tests (reference inputs, inline datums) — keep manual (has commented compile_definitions):
add_executable(test_sign_tx_babbage generated/sign_tx/test_sign_tx_babbage.c)
target_link_libraries(test_sign_tx_babbage PUBLIC cmocka gcov cardano_sign_tx_core)
#target_compile_definitions(test_sign_tx_babbage PRIVATE TRACE_TX_HASH_BUILDER)
add_test(test_sign_tx_babbage test_sign_tx_babbage)

# Conway era tests with governance certificates
cardano_unit_test(test_sign_tx_conway
    SOURCES generated/sign_tx/test_sign_tx_conway.c
    LIBS cardano_sign_tx_core)

# Conway era tests without certificates (treasury/donation)
cardano_unit_test(test_sign_tx_conway_without_certificates
    SOURCES generated/sign_tx/test_sign_tx_conway_without_certificates.c
    LIBS cardano_sign_tx_core)

# Conway era voting procedures tests
cardano_unit_test(test_sign_tx_conway_voting
    SOURCES generated/sign_tx/test_sign_tx_conway_voting.c
    LIBS cardano_sign_tx_core)

# Multisig tests
cardano_unit_test(test_sign_tx_multisig
    SOURCES generated/sign_tx/test_sign_tx_multisig.c
    LIBS cardano_sign_tx_core)

# Pool registration tests
cardano_unit_test(test_sign_tx_pool_registration
    SOURCES generated/sign_tx/test_sign_tx_pool_registration.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_security_policy_certificates
    SOURCES test_security_policy_certificates.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_security_policy_collateral
    SOURCES test_security_policy_collateral.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_security_policy_reference_input
    SOURCES test_security_policy_reference_input.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_security_policy_witness
    SOURCES test_security_policy_witness.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_sign_tx_deny_tests
    SOURCES generated/sign_tx/test_sign_tx_deny_tests.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_sign_tx_deny_tests_real_alloc
    SOURCES generated/sign_tx/test_sign_tx_deny_tests.c
    LIBS cardano_sign_tx_core_real_alloc)

cardano_unit_test(test_handler_denies_tx
    SOURCES test_handler_denies_tx.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_dispatcher_interleaving
    SOURCES
        test_dispatcher_interleaving.c
        mock_sources/mock_globals.c
        ../../src/apdu/dispatcher.c
    LIBS mock_printf)

cardano_unit_test(test_handler_state_machines
    SOURCES test_handler_state_machines.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_handler_sign_tx_swap
    SOURCES test_handler_sign_tx_swap.c
    LIBS cardano_sign_tx_core_swap)

cardano_unit_test(test_sign_tx_witness_nbgl_reject
    SOURCES test_sign_tx_witness_nbgl_reject.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_sign_tx_streaming_nbgl_reject
    SOURCES test_sign_tx_streaming_nbgl_reject.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_sign_msg_nbgl_reject
    SOURCES test_sign_msg_nbgl_reject.c
    LIBS cardano_sign_msg_core)

cardano_unit_test(test_handler_denies_sign_msg
    SOURCES
        test_handler_denies_sign_msg.c
        test_utils/io_capture.c
    LIBS cardano_sign_msg_core)

cardano_unit_test(test_sign_opcert_nbgl_reject
    SOURCES
        test_sign_opcert_nbgl_reject.c
        ../../src/handler/sign_opcert.c
        ../../src/opcert/opcert_parse.c
        ../../src/ui/ui_display_opcert.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_sign_cvote_nbgl_reject
    SOURCES test_sign_cvote_nbgl_reject.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_cvote_aux_data_ui
    SOURCES test_cvote_aux_data_ui.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_tx_parser
    SOURCES test_tx_parser.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_tx_parse_outputs
    SOURCES test_tx_parse_outputs.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_tx_parse_certificates
    SOURCES test_tx_parse_certificates.c
    LIBS cardano_sign_tx_core)

# test_cvote_parser: keep manual (needs target_link_options)
add_executable(test_cvote_parser test_cvote_parser.c)
target_link_libraries(test_cvote_parser PUBLIC cmocka gcov cardano_sign_tx_core)
target_link_options(test_cvote_parser PRIVATE -Wl,--wrap=parse_output_destination)
add_test(test_cvote_parser test_cvote_parser)

cardano_unit_test(test_cardano_parsers
    SOURCES test_cardano_parsers.c
    LIBS parsers_lib cardano_buffer_lib mock_printf)

cardano_unit_test(test_tx_utils
    SOURCES test_tx_utils.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_cvote_deny_tests
    SOURCES generated/cvote/test_cvote_deny_tests.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_handler_denies_cvote
    SOURCES
        test_handler_denies_cvote.c
        test_utils/io_capture.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_opcert
    SOURCES
        generated/opcert/test_opcert.c
        test_utils/hexUtils.c
        ../../src/handler/sign_opcert.c
        ../../src/opcert/opcert_parse.c
        ../../src/ui/ui_display_opcert.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_opcert_deny_tests
    SOURCES
        generated/opcert/test_opcert_deny_tests.c
        test_utils/hexUtils.c
        ../../src/handler/sign_opcert.c
        ../../src/opcert/opcert_parse.c
        ../../src/ui/ui_display_opcert.c
    LIBS cardano_sign_tx_core)

cardano_unit_test(test_handler_denies_opcert
    SOURCES
        test_handler_denies_opcert.c
        ../../src/handler/sign_opcert.c
        ../../src/opcert/opcert_parse.c
        ../../src/ui/ui_display_opcert.c
    LIBS cardano_sign_tx_core)


# Common sources for address derivation tests
set(DERIVE_ADDRESS_COMMON_SOURCES
    mock_sources/mock_globals.c
    ../../src/handler/derive_address.c
    ../../src/keyDerivation/keyDerivation.c
    ../../src/addressUtils/addressUtilsShelley.c
    ../../src/addressUtils/addressUtilsByron.c
    ../../src/addressUtils/bip44.c
    ../../src/transaction/tx_utils.c
    ../../src/cardano_tokens/cardano_tokens.c
    ../../src/securityPolicy/securityPolicy.c
    ../../src/securityPolicy/securityPolicy_privkey.c
    ../../src/app_context.c
    ../../src/utils/mem.c
    ../../src/cardano_tokens/cardano_tokens.c
    ../../src/ui/ui_utils.c
    ../../src/ui/ui_warnings.c
    ../../src/ui/ui_formatters.c
    ../../src/ui/ui_address_fields.c
    ../../src/ui/ui_display_address_derivation.c
    ${UNIT_TEST_MEM_UTILS_STUB}
    mock_sources/glyphs_mock.c
    mock_sources/nbgl_mock.c
    mock_sources/hex_stub.c
    test_utils/io_capture.c
)
# Common libraries for address derivation tests
set(DERIVE_ADDRESS_COMMON_LIBS
    hex_utils
    base58
    bech32_lib
    bip44_real
    cardano_buffer_lib
    cbor_lib
    blake2b_lib
    sha3_lib
    hash_mocks_lib
    crypto_mocks_lib
    buffer
    write
    read
    varint
    bip32
    cx_crc_support
    mock_printf
    parsers_lib
)
# Create a static library for address derivation core (reusable across tests)
add_library(cardano_derive_address_core STATIC ${DERIVE_ADDRESS_COMMON_SOURCES})
target_link_libraries(cardano_derive_address_core PUBLIC ${DERIVE_ADDRESS_COMMON_LIBS})

cardano_unit_test(test_derive_address_deny_tests
    SOURCES generated/derive_address/test_derive_address_deny_tests.c
    LIBS cardano_derive_address_core)

cardano_unit_test(test_derive_address
    SOURCES generated/derive_address/test_derive_address.c
    LIBS cardano_derive_address_core)

cardano_unit_test(test_ui_address_fields
    SOURCES test_ui_address_fields.c
    LIBS cardano_derive_address_core mock_printf)

cardano_unit_test(test_derive_address_nbgl_reject
    SOURCES test_derive_address_nbgl_reject.c
    LIBS cardano_derive_address_core)

set(PUBKEY_COMMON_SOURCES
    mock_sources/mock_globals.c
    ../../src/handler/get_public_key.c
    ../../src/keyDerivation/keyDerivation.c
    ../../src/addressUtils/addressUtilsShelley.c
    ../../src/addressUtils/addressUtilsByron.c
    ../../src/addressUtils/bip44.c
    ../../src/transaction/tx_utils.c
    ../../src/cardano_tokens/cardano_tokens.c
    ../../src/securityPolicy/securityPolicy.c
    ../../src/securityPolicy/securityPolicy_privkey.c
    ../../src/app_context.c
    ../../src/utils/mem.c
    ../../src/ui/ui_utils.c
    ../../src/ui/ui_warnings.c
    ../../src/ui/ui_display_pubkey.c
    ${UNIT_TEST_MEM_UTILS_STUB}
    mock_sources/glyphs_mock.c
    mock_sources/nbgl_mock.c
    mock_sources/hex_stub.c
    test_utils/io_capture.c
)
set(PUBKEY_COMMON_LIBS
    hex_utils
    base58
    bech32_lib
    bip44_real
    cardano_buffer_lib
    cbor_lib
    blake2b_lib
    sha3_lib
    hash_mocks_lib
    crypto_mocks_lib
    buffer
    write
    read
    varint
    bip32
    cx_crc_support
    mock_printf
    parsers_lib
)
add_library(cardano_pubkey_core STATIC ${PUBKEY_COMMON_SOURCES})
target_link_libraries(cardano_pubkey_core PUBLIC ${PUBKEY_COMMON_LIBS})

cardano_unit_test(test_pubkey_nbgl_reject
    SOURCES test_pubkey_nbgl_reject.c
    LIBS cardano_pubkey_core)

cardano_unit_test(test_pubkey
    SOURCES generated/pubkey/test_pubkey.c
    LIBS cardano_pubkey_core)

cardano_unit_test(test_pubkey_deny_tests
    SOURCES generated/pubkey/test_pubkey_deny_tests.c
    LIBS cardano_pubkey_core)

set(SIGN_MSG_COMMON_SOURCES
    mock_sources/mock_globals.c
    ../../src/app_context.c
    $ENV{BOLOS_SDK}/lib_lists/lists.c
    ../../src/utils/mem.c
    ../../src/handler/sign_msg.c
    ../../src/messageSigning/messageSigning.c
    ../../src/keyDerivation/keyDerivation.c
    ../../src/securityPolicy/securityPolicy.c
    ../../src/securityPolicy/securityPolicy_privkey.c
    ../../src/addressUtils/addressUtilsShelley.c
    ../../src/addressUtils/addressUtilsByron.c
    ../../src/addressUtils/bip44.c
    ../../src/cardano_tokens/cardano_tokens.c
    ../../src/parsers/cardano_parsers.c
    ../../src/utils/cardano_buffer.c
    ../../src/utils/cbor.c
    ../../src/utils/cbor_canonical.c
    ../../src/utils/textUtils.c
    ../../src/ui/ui_utils.c
    ../../src/ui/ui_warnings.c
    ../../src/ui/ui_formatters.c
    ../../src/ui/ui_sign_msg.c
    ../../src/transaction/tx_utils.c
    ${UNIT_TEST_MEM_UTILS_STUB}
    mock_sources/glyphs_mock.c
    mock_sources/nbgl_mock.c
    mock_sources/hex_stub.c
    test_utils/io_capture.c
)
set(SIGN_MSG_COMMON_LIBS
    text_utils
    hex_utils
    base58
    bech32_lib
    bip44_real
    cardano_buffer_lib
    cbor_lib
    blake2b_lib
    sha3_lib
    hash_mocks_lib
    crypto_mocks_lib
    buffer
    write
    read
    varint
    bip32
    cx_crc_support
    mock_printf
    parsers_lib
)
add_library(cardano_sign_msg_core STATIC ${SIGN_MSG_COMMON_SOURCES})
target_link_libraries(cardano_sign_msg_core PUBLIC ${SIGN_MSG_COMMON_LIBS})

set(DERIVE_NATIVE_SCRIPT_COMMON_SOURCES
    ../../src/deriveNativeScriptHash/derive_native_script_hash_builder.c
    ../../src/handler/derive_native_script_hash.c
    ../../src/keyDerivation/keyDerivation.c
    ../../src/parsers/cardano_parsers.c
    ../../src/addressUtils/addressUtilsShelley.c
    ../../src/addressUtils/addressUtilsByron.c
    ../../src/addressUtils/bip44.c
    ../../src/transaction/tx_utils.c
    ../../src/cardano_tokens/cardano_tokens.c
    ../../src/securityPolicy/securityPolicy.c
    ../../src/securityPolicy/securityPolicy_privkey.c
    ../../src/app_context.c
    ../../src/utils/mem.c
    ../../src/ui/ui_utils.c
    ../../src/ui/ui_warnings.c
    ../../src/ui/ui_formatters.c
    ../../src/ui/ui_display_native_script_hash.c
    ${UNIT_TEST_MEM_UTILS_STUB}
    mock_sources/mock_globals.c
    mock_sources/glyphs_mock.c
    mock_sources/nbgl_mock.c
    mock_sources/hex_stub.c
    mock_sources/io_stub.c
    test_native_script_utils.c
)
set(DERIVE_NATIVE_SCRIPT_COMMON_LIBS
    hex_utils
    base58
    bech32_lib
    bip44_real
    cardano_buffer_lib
    cbor_lib
    blake2b_lib
    sha3_lib
    hash_mocks_lib
    crypto_mocks_lib
    buffer
    write
    read
    varint
    bip32
    cx_crc_support
    mock_printf
    parsers_lib
)
add_library(cardano_derive_native_script_core STATIC ${DERIVE_NATIVE_SCRIPT_COMMON_SOURCES})
target_link_libraries(cardano_derive_native_script_core PUBLIC ${DERIVE_NATIVE_SCRIPT_COMMON_LIBS})

cardano_unit_test(test_native_script
    SOURCES generated/native_script/test_native_script.c
    LIBS cardano_derive_native_script_core)

cardano_unit_test(test_native_script_deny_tests
    SOURCES generated/native_script/test_native_script_deny_tests.c
    LIBS cardano_derive_native_script_core)

cardano_unit_test(test_handler_reset_semantics
    SOURCES test_handler_reset_semantics.c
    LIBS cardano_derive_native_script_core)

cardano_unit_test(test_app_main_exception_handling
    SOURCES
        test_app_main_exception_handling.c
        ../../src/app_main_utils.c
        ../../src/app_context.c
        ../../src/utils/mem.c
        ${UNIT_TEST_MEM_UTILS_STUB}
        mock_sources/mock_globals.c
    LIBS mock_printf)

cardano_unit_test(test_app_main_exception_handling_real_alloc
    SOURCES
        test_app_main_exception_handling.c
        ../../src/app_main_utils.c
        ../../src/app_context.c
        ../../src/utils/mem.c
        ${UNIT_TEST_MEM_UTILS_REAL_ALLOC}
        mock_sources/mock_globals.c
    LIBS mock_printf)

cardano_unit_test(test_native_script_state_machine
    SOURCES test_native_script_state_machine.c
    LIBS cardano_derive_native_script_core)

cardano_unit_test(test_native_script_init_ui_completion
    SOURCES test_native_script_init_ui_completion.c
    LIBS cardano_derive_native_script_core)

cardano_unit_test(test_native_script_nbgl_reject
    SOURCES test_native_script_nbgl_reject.c
    LIBS cardano_derive_native_script_core)

cardano_unit_test(test_native_script_status_text
    SOURCES test_native_script_status_text.c
    LIBS cardano_derive_native_script_core)

cardano_unit_test(test_native_script_ui_render
    SOURCES test_native_script_ui_render.c
    LIBS cardano_derive_native_script_core)
