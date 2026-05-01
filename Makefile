# ****************************************************************************
#    Ledger App Cardano
#    (c) 2025 Ledger SAS and Vacuumlabs
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.target

########################################
#        Mandatory configuration       #
########################################
# Application name
APPNAME = "Cardano ADA"

# Application version
APPVERSION_M = 8
APPVERSION_N = 0
APPVERSION_P = 2
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

# Application source files
APP_SOURCE_PATH += src

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOX = icons/icon_ada_nanox.gif
ICON_NANOSP = icons/icon_ada_nanox.gif
ICON_STAX = icons/icon_ada_stax.gif
ICON_FLEX = icons/icon_ada_flex.gif
ICON_APEX_P = icons/icon_ada_apex.gif
ICON_APEX_M = icons/icon_ada_apex.gif

# Application allowed derivation curves.
# Possibles curves are: secp256k1, secp256r1, ed25519 and bls12381g1
# If your app needs it, you can specify multiple curves by using:
# `CURVE_APP_LOAD_PARAMS = <curve1> <curve2>`
CURVE_APP_LOAD_PARAMS = ed25519

# Application allowed derivation paths.
# You should request a specific path for your app.
# This serve as an isolation mechanism.
# Most application will have to request a path according to the BIP-0044
# and SLIP-0044 standards.
# If your app needs it, you can specify multiple path by using:
# `PATH_APP_LOAD_PARAMS = "44'/1'" "45'/1'"`
PATH_APP_LOAD_PARAMS = "44'/1815'" "1852'/1815'" "1853'/1815'" "1854'/1815'" "1855'/1815'" "1694'/1815'"

# Setting to allow building variant applications
# - <VARIANT_PARAM> is the name of the parameter which should be set
#   to specify the variant that should be build.
# - <VARIANT_VALUES> a list of variant that can be build using this app code.
#   * It must at least contains one value.
#   * Values can be the app ticker or anything else but should be unique.
VARIANT_PARAM = COIN
VARIANT_VALUES = cardano_ada

# Enabling DEBUG flag will enable PRINTF and disable optimizations
# Note: The VS Code Ledger plugin's "selectedUseCase" setting should control this
#DEBUG = 1

# When DEBUG is enabled, add DEBUG as a preprocessor define so #ifdef DEBUG works in code
ifneq ($(DEBUG), 0)
    DEFINES += DEBUG
endif

# Enable OS-level stack consumption monitoring
# Pass via command line: make DEBUG_OS_STACK_CONSUMPTION=1
# Then run ragger tests with: pytest ... --get-stack-consumption
# Requires ragger >= 1.44.0
#DEBUG_OS_STACK_CONSUMPTION = 1

ifneq ($(DEBUG_OS_STACK_CONSUMPTION),)
    DEFINES += DEBUG_OS_STACK_CONSUMPTION
endif

########################################
#     Application custom permissions   #
########################################
# See SDK `include/appflags.h` for the purpose of each permission
#HAVE_APPLICATION_FLAG_DERIVE_MASTER = 1
#HAVE_APPLICATION_FLAG_GLOBAL_PIN = 1
#HAVE_APPLICATION_FLAG_LIBRARY = 1

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1
#ENABLE_NFC = 1
ENABLE_NBGL_FOR_NANO_DEVICES = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1
#ENABLE_NBGL_KEYBOARD = 1
#ENABLE_NBGL_KEYPAD = 1


########################################
#            Swap support              #
########################################
ENABLE_SWAP = 1

########################################
#          Features disablers          #
########################################
# These advanced settings allow to disable some feature that are by
# default enabled in the SDK `Makefile.standard_app`.
#DISABLE_STANDARD_APP_FILES = 1
#DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1 # To allow custom size declaration
#DISABLE_STANDARD_APP_DEFINES = 1 # Will set all the following disablers
#DISABLE_STANDARD_SNPRINTF = 1
#DISABLE_STANDARD_USB = 1
#DISABLE_STANDARD_WEBUSB = 1
#DISABLE_DEBUG_LEDGER_ASSERT = 1

########################################
#       Dynamic memory allocation      #
########################################
ENABLE_DYNAMIC_ALLOC = 1

########################################
#       Lists library support          #
########################################
ENABLE_LISTS_LIBRARY = 1

include $(BOLOS_SDK)/Makefile.standard_app
