cmake_minimum_required(VERSION 3.14)

if(${CMAKE_VERSION} VERSION_LESS 3.14)
  cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(CardanoFuzzers
        VERSION 1.0
        DESCRIPTION "Fuzzing harnesses for Cardano Ledger app"
        LANGUAGES C)

if(NOT DEFINED BOLOS_SDK)
  message(FATAL_ERROR "BOLOS_SDK must be defined, CMake will exit.")
  return()
endif()

# Pull in the SDK fuzzing framework: secure_sdk target, macro extraction,
# sanitizer/coverage flags, mock libraries, etc.
add_subdirectory(${BOLOS_SDK}/fuzzing ${CMAKE_CURRENT_BINARY_DIR}/ledger-secure-sdk EXCLUDE_FROM_ALL)

set(DEFINES FUZZ HAVE_SWAP)

set(APP_SRC ${CMAKE_SOURCE_DIR}/../../src)

file(GLOB_RECURSE C_SOURCES
  ${APP_SRC}/*.c
  ${CMAKE_SOURCE_DIR}/mock/*.c
  ${CMAKE_SOURCE_DIR}/src/fuzz_utils.c
)

list(REMOVE_ITEM C_SOURCES
  ${APP_SRC}/app_main.c
  ${APP_SRC}/handler/debug_settings.c
)

add_library(code_lib ${C_SOURCES})

target_include_directories(
  code_lib
  PUBLIC ${CMAKE_SOURCE_DIR}/src
         ${CMAKE_SOURCE_DIR}/mock
         ${CMAKE_SOURCE_DIR}/include
         ${APP_SRC}
         ${APP_SRC}/bech32
         ${APP_SRC}/addressUtils
         ${APP_SRC}/apdu
         ${APP_SRC}/cardano_tokens
         ${APP_SRC}/cvote
         ${APP_SRC}/crypto
         ${APP_SRC}/deriveNativeScriptHash
         ${APP_SRC}/handler
         ${APP_SRC}/keyDerivation
         ${APP_SRC}/memory
         ${APP_SRC}/messageSigning
         ${APP_SRC}/opcert
         ${APP_SRC}/parsers
         ${APP_SRC}/securityPolicy
         ${APP_SRC}/swap
         ${APP_SRC}/transaction
         ${APP_SRC}/txHashBuilder
         ${APP_SRC}/ui
         ${APP_SRC}/utils
)

target_link_libraries(code_lib PUBLIC secure_sdk)
target_compile_definitions(code_lib PUBLIC ${DEFINES} FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)

# Suppress alignment sanitizer: the app uses packed struct accesses
# that trigger false positives with UBSan alignment checks.
target_compile_options(code_lib PUBLIC -fno-sanitize=alignment)
target_link_options(code_lib PUBLIC -fno-sanitize=alignment)

# Create the different fuzzing targets automatically
file(GLOB FUZZ_HARNESSES "${CMAKE_SOURCE_DIR}/harness/fuzz_*.c")

foreach(HARNESS_FILE ${FUZZ_HARNESSES})
  # Extract the base name of the file without extension
  get_filename_component(HARNESS_NAME ${HARNESS_FILE} NAME_WE)

  # Create the executable target
  add_executable(${HARNESS_NAME} ${HARNESS_FILE})

  # Define the compilation options
  target_compile_definitions(${HARNESS_NAME} PUBLIC macros FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)

  # Link against the secure_sdk and code_lib libraries
  target_link_libraries(${HARNESS_NAME} PUBLIC secure_sdk code_lib)

  # Override SDK's cx_ecdsa_verify_no_throw to avoid MemorySanitizer false positives
  target_link_options(${HARNESS_NAME} PRIVATE -Wl,--wrap=cx_ecdsa_verify_no_throw)

  # Neutralize the SDK's real os_explicit_zero_BSS_segment (called by swap param copy):
  # a live BSS wipe would clobber the fuzzer/sanitizer/heap globals.
  target_link_options(${HARNESS_NAME} PRIVATE -Wl,--wrap=os_explicit_zero_BSS_segment)

  message(STATUS "Creating fuzzer target: ${HARNESS_NAME}")
endforeach()
