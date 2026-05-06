/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "main_std_app.h"
#include "utils.h"

#include "globals.h"
#include "menu.h"
#include "ui_icons.h"
#include "cardano_settings.h"

//  -----------------------------------------------------------
//  ----------------------- HOME PAGE -------------------------
//  -----------------------------------------------------------

//  -----------------------------------------------------------
//  --------------------- SETTINGS MENU -----------------------
//  -----------------------------------------------------------
#define SETTING_INFO_NB 3
static const char* const INFO_TYPES[SETTING_INFO_NB] = {"Version", "Developer", "Copyright"};
static const char* const INFO_CONTENTS[SETTING_INFO_NB] = {APPVERSION, "Vacuumlabs", "(c) 2022 Ledger"};

// settings switches definitions
enum { SILENT_PUBKEY_EXPORT_TOKEN = FIRST_USER_TOKEN, EXPERT_MODE_TOKEN, BLIND_SIGNING_TOKEN };
enum { SILENT_PUBKEY_EXPORT_ID = 0, EXPERT_MODE_ID, BLIND_SIGNING_ID, SETTINGS_SWITCHES_NB };

static nbgl_contentSwitch_t switches[SETTINGS_SWITCHES_NB] = {0};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = SETTING_INFO_NB,
    .infoTypes = INFO_TYPES,
    .infoContents = INFO_CONTENTS,
};

static uint8_t initSettingPage;
static void controls_callback(int token, uint8_t index, int page);

// settings menu definition
#define SETTING_CONTENTS_NB 1
static const nbgl_content_t contents[SETTING_CONTENTS_NB] = {
    {.type = SWITCHES_LIST,
     .content.switchesList.nbSwitches = SETTINGS_SWITCHES_NB,
     .content.switchesList.switches = switches,
     .contentActionCallback = controls_callback}};

static const nbgl_genericContents_t settingContents = {.callbackCallNeeded = false,
                                                       .contentsList = contents,
                                                       .nbContents = SETTING_CONTENTS_NB};

static void controls_callback(int token, uint8_t index, int page) {
    UNUSED(index);

    initSettingPage = page;
    TRACE("Menu controls_callback token=%d page=%d", token, page);

    uint8_t switch_value;
    switch (token) {
        case SILENT_PUBKEY_EXPORT_TOKEN:
            // toggle the switch value
            switch_value = flip_bool_setting(N_storage.silent_pubkey_export_enabled);
            switches[SILENT_PUBKEY_EXPORT_ID].initState = (nbgl_state_t) switch_value;
            // store the new setting value in NVM
            nvm_write((void*) &N_storage.silent_pubkey_export_enabled, &switch_value, 1);
            break;

        case EXPERT_MODE_TOKEN:
            // toggle the switch value
            switch_value = flip_bool_setting(N_storage.expert_mode_enabled);
            switches[EXPERT_MODE_ID].initState = (nbgl_state_t) switch_value;
            // store the new setting value in NVM
            nvm_write((void*) &N_storage.expert_mode_enabled, &switch_value, 1);
            break;

        case BLIND_SIGNING_TOKEN:
            // toggle the switch value
            switch_value = flip_bool_setting(N_storage.blind_signing_enabled);
            switches[BLIND_SIGNING_ID].initState = (nbgl_state_t) switch_value;
            // store the new setting value in NVM
            nvm_write((void*) &N_storage.blind_signing_enabled, &switch_value, 1);
            break;

        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Unknown menu token");
            break;
            // LCOV_EXCL_STOP
    }
}

// home page definition
void ui_menu_main(void) {
    // Initialize switches data
    switches[SILENT_PUBKEY_EXPORT_ID].initState =
        (nbgl_state_t) silent_pubkey_export_setting_value();
#ifdef SCREEN_SIZE_WALLET
    switches[SILENT_PUBKEY_EXPORT_ID].text = "Silent public key export";
    switches[SILENT_PUBKEY_EXPORT_ID].subText = "Allow usual public keys to be exported silently";
#else
    switches[SILENT_PUBKEY_EXPORT_ID].text = "Silent pubkeys";
    switches[SILENT_PUBKEY_EXPORT_ID].subText = "Allow silent export\nof usual pubkeys";
#endif
    switches[SILENT_PUBKEY_EXPORT_ID].token = SILENT_PUBKEY_EXPORT_TOKEN;
#ifdef HAVE_PIEZO_SOUND
    switches[SILENT_PUBKEY_EXPORT_ID].tuneId = TUNE_TAP_CASUAL;
#endif

    switches[EXPERT_MODE_ID].initState = (nbgl_state_t) expert_mode_setting_value();
    switches[EXPERT_MODE_ID].text = "Expert mode";
#ifdef SCREEN_SIZE_WALLET
    switches[EXPERT_MODE_ID].subText = "Show technical details in transactions";
#else
    switches[EXPERT_MODE_ID].subText = "Show technical\ntx details";
#endif
    switches[EXPERT_MODE_ID].token = EXPERT_MODE_TOKEN;
#ifdef HAVE_PIEZO_SOUND
    switches[EXPERT_MODE_ID].tuneId = TUNE_TAP_CASUAL;
#endif

    switches[BLIND_SIGNING_ID].initState = (nbgl_state_t) blind_signing_setting_value();
    switches[BLIND_SIGNING_ID].text = "Blind signing";
    switches[BLIND_SIGNING_ID].subText = "Enable blind signing for long transactions";
    switches[BLIND_SIGNING_ID].token = BLIND_SIGNING_TOKEN;
#ifdef HAVE_PIEZO_SOUND
    switches[BLIND_SIGNING_ID].tuneId = TUNE_TAP_CASUAL;
#endif

    TRACE(
        "Calling nbgl_useCaseHomeAndSettings(APPNAME), expert=%d, silentPubkey=%d, blindSigning=%d",
        expert_mode_setting_value(),
        silent_pubkey_export_setting_value(),
        blind_signing_setting_value());
    nbgl_useCaseHomeAndSettings(APPNAME,
                                &ICON_APP_HOME,
                                NULL,
                                INIT_HOME_PAGE,
                                &settingContents,
                                &infoList,
                                NULL,
                                app_exit);
}
