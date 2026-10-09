#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <ShlObj.h>
#include <powrprof.h>
#include <cstddef>
#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <string>
#include <system_error>

#pragma comment(lib, "PowrProf.lib")

namespace fs = std::filesystem;

namespace {

    constexpr const wchar_t* search_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Search";
    constexpr const wchar_t* advanced_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced";
    constexpr const wchar_t* taskband_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Taskband";
    constexpr const wchar_t* feeds_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Feeds";
    constexpr const wchar_t* policies_explorer_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";
    constexpr const wchar_t* dsh_policy_key = L"SOFTWARE\\Policies\\Microsoft\\Dsh";
    constexpr const wchar_t* feeds_policy_key = L"SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Feeds";
    constexpr const wchar_t* explorer_policy_key = L"SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer";
    constexpr const wchar_t* run_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    constexpr const wchar_t* startup_approved_run_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run";
    constexpr const wchar_t* immersive_shell_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ImmersiveShell";
    constexpr const wchar_t* data_collection_policy_key = L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection";
    constexpr const wchar_t* system_policy_key = L"SOFTWARE\\Policies\\Microsoft\\Windows\\System";
    constexpr const wchar_t* appcompat_policy_key = L"SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat";
    constexpr const wchar_t* input_personalization_key = L"SOFTWARE\\Microsoft\\InputPersonalization";
    constexpr const wchar_t* personalize_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize";
    constexpr const wchar_t* lock_screen_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lock Screen";
    constexpr const wchar_t* notification_settings_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings";
    constexpr const wchar_t* stuck_rects_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StuckRects3";
    constexpr const wchar_t* accent_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Accent";
    constexpr const wchar_t* dwm_key = L"SOFTWARE\\Microsoft\\Windows\\DWM";

    // No trailing backslash: some tools append "\name" to TEMP and end up with a double separator.
    constexpr const wchar_t* temp_dir = L"C:\\TEMP";
    constexpr const wchar_t* user_environment_key = L"Environment";
    constexpr const wchar_t* system_environment_key = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
    constexpr const wchar_t* temp_variables[] = { L"TEMP", L"TMP" };

    constexpr const wchar_t* visual_effects_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects";

    constexpr BYTE autohide_flag = 0x01;

    constexpr BYTE overcast_palette[32] = {
        0xC5, 0xC5, 0xC5, 0x00,   // light 3  (approximate)
        0xAE, 0xAE, 0xAE, 0x00,   // light 2  (approximate)
        0x97, 0x97, 0x97, 0x00,   // light 1  (approximate)
        0x76, 0x76, 0x76, 0x00,   // base: Overcast
        0x54, 0x54, 0x54, 0x00,   // dark 1   (approximate)
        0x3B, 0x3B, 0x3B, 0x00,   // dark 2   (approximate)
        0x23, 0x23, 0x23, 0x00,   // dark 3   (approximate)
        0x88, 0x17, 0x98, 0x00,   // trailing entry seen in typical palettes
    };

    constexpr GUID ultimate_performance_scheme =
    { 0xe9a42b02, 0xd5df, 0x448d, { 0xaa, 0x00, 0x03, 0xf1, 0x47, 0x49, 0xeb, 0x61 } };
    constexpr GUID video_subgroup =
    { 0x7516b95f, 0xf776, 0x4464, { 0x8c, 0x53, 0x06, 0x16, 0x7f, 0x40, 0xcc, 0x99 } };
    constexpr GUID video_timeout =
    { 0x3c0bc021, 0xc8a8, 0x4e07, { 0xa9, 0x73, 0x6b, 0x14, 0xcb, 0xcb, 0x2b, 0x7e } };
    constexpr GUID sleep_subgroup =
    { 0x238c9fa8, 0x0aad, 0x41ed, { 0x83, 0xf4, 0x97, 0xbe, 0x24, 0x2c, 0x8f, 0x20 } };
    constexpr GUID sleep_timeout =
    { 0x29f6c1db, 0x86da, 0x48c5, { 0x9f, 0xdb, 0xf2, 0xb6, 0x7b, 0x1f, 0x44, 0xda } };

    struct registry_setting {
        HKEY root;
        const wchar_t* sub_key;
        const wchar_t* value_name;
        DWORD value;
    };

    struct power_setting {
        GUID subgroup;
        GUID setting;
    };

    const registry_setting interface_settings[] = {
        { HKEY_CURRENT_USER,  search_key,             L"SearchboxTaskbarMode",      0 },
        { HKEY_CURRENT_USER,  advanced_key,           L"ShowCortanaButton",         0 },
        { HKEY_CURRENT_USER,  advanced_key,           L"ShowTaskViewButton",        0 },
        { HKEY_CURRENT_USER,  advanced_key,           L"TaskbarDa",                 0 },
        { HKEY_CURRENT_USER,  advanced_key,           L"ShowNotificationIcon",      0 },
        { HKEY_CURRENT_USER,  advanced_key,           L"MultiTaskingAltTabFilter",  3 },
        { HKEY_CURRENT_USER,  policies_explorer_key,  L"HideSCAMeetNow",            1 },
        { HKEY_CURRENT_USER,  feeds_key,              L"ShellFeedsTaskbarViewMode", 2 },
        { HKEY_CURRENT_USER,  explorer_policy_key,    L"DisableNotificationCenter", 1 },
        { HKEY_LOCAL_MACHINE, dsh_policy_key,         L"AllowNewsAndInterests",     0 },
        { HKEY_LOCAL_MACHINE, feeds_policy_key,       L"EnableFeeds",               0 },
    };

    const registry_setting system_settings[] = {
        { HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Clipboard", L"EnableClipboardHistory",             1 },
        { HKEY_CURRENT_USER, immersive_shell_key,               L"TabletMode",                         0 },
        { HKEY_CURRENT_USER, immersive_shell_key,               L"SignInMode",                         1 },
        { HKEY_CURRENT_USER, immersive_shell_key,               L"ConvertibleSlateModePromptPreference", 0 },
    };

    const registry_setting personalization_settings[] = {
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Wallpapers", L"BackgroundType", 1 },
        { HKEY_CURRENT_USER,  personalize_key,            L"AppsUseLightTheme",                       0 },
        { HKEY_CURRENT_USER,  personalize_key,            L"SystemUsesLightTheme",                    0 },
        { HKEY_CURRENT_USER,  lock_screen_key,            L"LockScreenWidgetsEnabled",                0 },
        { HKEY_CURRENT_USER,  notification_settings_key,  L"NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK", 0 },
        { HKEY_LOCAL_MACHINE, system_policy_key,          L"DisableLockScreenAppNotifications",       1 },
        { HKEY_LOCAL_MACHINE, dsh_policy_key,             L"DisableWidgetsOnLockScreen",              1 },
        { HKEY_CURRENT_USER,  advanced_key,               L"TaskbarSmallIcons",                       1 },
        { HKEY_CURRENT_USER,  advanced_key,               L"TaskbarSi",                               0 },
        { HKEY_CURRENT_USER,  L"Control Panel\\Desktop",  L"AutoColorization",                        0 },
        { HKEY_CURRENT_USER,  accent_key,                 L"AccentColorMenu",                         0xFF767676 },
        { HKEY_CURRENT_USER,  accent_key,                 L"StartColorMenu",                          0xFF767676 },
        { HKEY_CURRENT_USER,  dwm_key,                    L"AccentColor",                             0xFF767676 },
        { HKEY_CURRENT_USER,  dwm_key,                    L"ColorizationColor",                       0xC4767676 },
        { HKEY_CURRENT_USER,  dwm_key,                    L"ColorizationAfterglow",                   0xC4767676 },
    };

    // Performance Options > Visual Effects, the entries that live in the registry rather than behind
    // SystemParametersInfo. VisualFXSetting 3 is "Custom", which is what the dialog switches to when
    // you pick "Adjust for best performance" and then tick "Smooth edges of screen fonts".
    const registry_setting visual_effect_settings[] = {
        { HKEY_CURRENT_USER, visual_effects_key, L"VisualFXSetting",          3 },
        { HKEY_CURRENT_USER, advanced_key,       L"TaskbarAnimations",        0 },  // animations in the taskbar
        { HKEY_CURRENT_USER, advanced_key,       L"ListviewAlphaSelect",      0 },  // translucent selection rectangle
        { HKEY_CURRENT_USER, advanced_key,       L"ListviewShadow",           0 },  // drop shadows for desktop icon labels
        { HKEY_CURRENT_USER, advanced_key,       L"IconsOnly",                1 },  // 1 = icons instead of thumbnails
        { HKEY_CURRENT_USER, dwm_key,            L"EnableAeroPeek",           0 },  // Peek
        { HKEY_CURRENT_USER, dwm_key,            L"AlwaysHibernateThumbnails", 0 }, // save taskbar thumbnail previews
    };

    const registry_setting telemetry_settings[] = {
        { HKEY_LOCAL_MACHINE, data_collection_policy_key, L"AllowTelemetry",                0 },
        { HKEY_LOCAL_MACHINE, data_collection_policy_key, L"DoNotShowFeedbackNotifications", 1 },
        { HKEY_LOCAL_MACHINE, data_collection_policy_key, L"LimitDiagnosticLogCollection",  1 },
        { HKEY_LOCAL_MACHINE, data_collection_policy_key, L"LimitDumpCollection",           1 },
        { HKEY_LOCAL_MACHINE, data_collection_policy_key, L"DisableOneSettingsDownloads",   1 },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection", L"AllowTelemetry", 0 },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\AutoLogger-Diagtrack-Listener", L"Start", 0 },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\AdvertisingInfo", L"DisabledByGroupPolicy", 1 },
        { HKEY_LOCAL_MACHINE, system_policy_key,          L"EnableActivityFeed",            0 },
        { HKEY_LOCAL_MACHINE, system_policy_key,          L"PublishUserActivities",         0 },
        { HKEY_LOCAL_MACHINE, system_policy_key,          L"UploadUserActivities",          0 },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows", L"CEIPEnable", 0 },
        { HKEY_LOCAL_MACHINE, appcompat_policy_key,       L"AITEnable",                     0 },
        { HKEY_LOCAL_MACHINE, appcompat_policy_key,       L"DisableInventory",              1 },
        { HKEY_LOCAL_MACHINE, appcompat_policy_key,       L"DisableUAR",                    1 },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting", L"Disabled", 1 },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", L"Enabled", 0 },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Privacy", L"TailoredExperiencesWithDiagnosticDataEnabled", 0 },
        { HKEY_CURRENT_USER,  input_personalization_key,  L"RestrictImplicitInkCollection", 1 },
        { HKEY_CURRENT_USER,  input_personalization_key,  L"RestrictImplicitTextCollection", 1 },
    };

    constexpr const wchar_t* telemetry_services[] = {
        L"DiagTrack",
        L"dmwappushservice",
    };

    constexpr const char* telemetry_tasks[] = {
        "\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
        "\\Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
        "\\Microsoft\\Windows\\Application Experience\\StartupAppTask",
        "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
        "\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip",
        "\\Microsoft\\Windows\\Autochk\\Proxy",
    };

    constexpr power_setting screen_sleep_settings[] = {
        { video_subgroup, video_timeout },
        { sleep_subgroup, sleep_timeout },
    };

    // Visual effects that SystemParametersInfo takes as a BOOL in pvParam.
    constexpr UINT visual_effect_actions[] = {
        SPI_SETCLIENTAREAANIMATION,     // animate controls and elements inside windows
        SPI_SETMENUANIMATION,           // fade or slide menus into view
        SPI_SETTOOLTIPANIMATION,        // fade or slide ToolTips into view
        SPI_SETMENUFADE,                // fade out menu items after clicking
        SPI_SETCURSORSHADOW,            // show shadows under mouse pointer
        SPI_SETDROPSHADOW,              // show shadows under windows
        SPI_SETCOMBOBOXANIMATION,       // slide open combo boxes
        SPI_SETLISTBOXSMOOTHSCROLLING,  // smooth-scroll list boxes
    };

    bool is_elevated() {
        static const bool elevated = [] {
            HANDLE token = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
                return false;
            }

            TOKEN_ELEVATION elevation{};
            DWORD size = 0;
            const bool result = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) &&
                elevation.TokenIsElevated != 0;
            CloseHandle(token);
            return result;
            }();
        return elevated;
    }

    bool report(bool ok, const wchar_t* success_message, const wchar_t* failure_message) {
        (ok ? std::wcout : std::wcerr) << (ok ? success_message : failure_message) << L'\n';
        return ok;
    }

    bool set_dword(const registry_setting& setting) {
        const LONG result = RegSetKeyValueW(
            setting.root,
            setting.sub_key,
            setting.value_name,
            REG_DWORD,
            &setting.value,
            sizeof(setting.value));

        if (result != ERROR_SUCCESS) {
            std::wcerr << L"failed to set " << setting.value_name << L" (error " << result << L")";
            if (result == ERROR_ACCESS_DENIED) {
                std::wcerr << L", blocked by Windows";
            }
            std::wcerr << L'\n';
            return false;
        }
        return true;
    }

    template <std::size_t count>
    bool apply_settings(const registry_setting(&settings)[count]) {
        const bool elevated = is_elevated();
        bool ok = true;
        int skipped = 0;

        for (const auto& setting : settings) {
            if (setting.root == HKEY_LOCAL_MACHINE && !elevated) {
                ++skipped;
                continue;
            }
            ok = set_dword(setting) && ok;
        }

        if (skipped > 0) {
            std::wcerr << skipped << L" machine-wide setting(s) skipped, run as administrator\n";
            ok = false;
        }
        return ok;
    }

    bool disable_telemetry_services() {
        if (!is_elevated()) {
            std::wcerr << L"telemetry services skipped, run as administrator\n";
            return false;
        }

        const SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (manager == nullptr) {
            std::wcerr << L"failed to open the service manager (error " << GetLastError() << L")\n";
            return false;
        }

        bool ok = true;
        for (const wchar_t* name : telemetry_services) {
            const SC_HANDLE service = OpenServiceW(manager, name, SERVICE_CHANGE_CONFIG | SERVICE_STOP);
            if (service == nullptr) {
                ok = ok && GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST;
                continue;
            }

            SERVICE_STATUS status{};
            ControlService(service, SERVICE_CONTROL_STOP, &status);
            ok = ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) && ok;
            CloseServiceHandle(service);
        }

        CloseServiceHandle(manager);
        return report(ok, L"Telemetry services disabled.", L"Failed to disable the telemetry services.");
    }

    bool disable_telemetry_tasks() {
        if (!is_elevated()) {
            std::wcerr << L"telemetry tasks skipped, run as administrator\n";
            return false;
        }

        std::size_t disabled = 0;
        for (const char* task : telemetry_tasks) {
            const std::string command = std::string("schtasks /Change /TN \"") + task + "\" /Disable >nul 2>&1";
            if (std::system(command.c_str()) == 0) {
                ++disabled;
            }
        }

        std::wcout << L"Disabled " << disabled << L" of " << std::size(telemetry_tasks)
            << L" telemetry scheduled tasks (tasks missing on this Windows build are skipped).\n";
        return true;
    }

    fs::path get_taskbar_pinned_folder_path() {
        PWSTR roaming_app_data = nullptr;
        const HRESULT hr = SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &roaming_app_data);

        fs::path path;
        if (SUCCEEDED(hr)) {
            path = fs::path(roaming_app_data) / L"Microsoft" / L"Internet Explorer" /
                L"Quick Launch" / L"User Pinned" / L"TaskBar";
        }
        CoTaskMemFree(roaming_app_data);
        return path;
    }

    bool clear_folder(const fs::path& folder) {
        std::error_code ec;
        if (!fs::exists(folder, ec)) {
            return !ec;
        }

        bool ok = true;
        for (fs::directory_iterator it(folder, ec), end; !ec && it != end; it.increment(ec)) {
            if (it->is_regular_file(ec)) {
                fs::remove(it->path(), ec);
            }
            if (ec) {
                ok = false;
                ec.clear();
            }
        }
        return ok && !ec;
    }

    bool delete_taskband_registry_key() {
        const LONG result = RegDeleteTreeW(HKEY_CURRENT_USER, taskband_key);
        return result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND;
    }

    void restart_explorer() {
        std::system("taskkill /f /im explorer.exe >nul 2>&1");
        std::system("start \"\" explorer.exe");
    }

    bool setup_power_plan() {
        GUID* new_scheme = nullptr;
        DWORD result = PowerDuplicateScheme(nullptr, &ultimate_performance_scheme, &new_scheme);
        if (result != ERROR_SUCCESS) {
            std::wcerr << L"failed to duplicate the power scheme (error " << result << L")\n";
            return false;
        }

        result = PowerSetActiveScheme(nullptr, new_scheme);
        LocalFree(new_scheme);

        return report(
            result == ERROR_SUCCESS,
            L"Ultimate Performance power plan created and activated.",
            L"Failed to activate the new power plan.");
    }

    bool disable_screen_sleep() {
        GUID* scheme = nullptr;
        DWORD result = PowerGetActiveScheme(nullptr, &scheme);
        if (result != ERROR_SUCCESS) {
            std::wcerr << L"failed to read the active power scheme (error " << result << L")\n";
            return false;
        }

        for (const auto& item : screen_sleep_settings) {
            if (result == ERROR_SUCCESS) {
                result = PowerWriteACValueIndex(nullptr, scheme, &item.subgroup, &item.setting, 0);
            }
            if (result == ERROR_SUCCESS) {
                result = PowerWriteDCValueIndex(nullptr, scheme, &item.subgroup, &item.setting, 0);
            }
        }
        if (result == ERROR_SUCCESS) {
            result = PowerSetActiveScheme(nullptr, scheme);
        }
        LocalFree(scheme);

        return report(
            result == ERROR_SUCCESS,
            L"Screen and sleep timeouts set to never.",
            L"Failed to change the screen and sleep timeouts.");
    }

    bool disable_onedrive_startup() {
        constexpr BYTE disabled_state[12] = { 0x03 };

        const LONG approved_result = RegSetKeyValueW(
            HKEY_CURRENT_USER,
            startup_approved_run_key,
            L"OneDrive",
            REG_BINARY,
            disabled_state,
            sizeof(disabled_state));

        const LONG run_result = RegDeleteKeyValueW(HKEY_CURRENT_USER, run_key, L"OneDrive");

        return report(
            approved_result == ERROR_SUCCESS &&
            (run_result == ERROR_SUCCESS || run_result == ERROR_FILE_NOT_FOUND),
            L"OneDrive startup disabled.",
            L"Failed to disable OneDrive startup.");
    }

    bool set_black_desktop_background() {
        constexpr wchar_t black[] = L"0 0 0";
        const LONG color_result = RegSetKeyValueW(
            HKEY_CURRENT_USER,
            L"Control Panel\\Colors",
            L"Background",
            REG_SZ,
            black,
            sizeof(black));

        const INT element = COLOR_BACKGROUND;
        const COLORREF color = RGB(0, 0, 0);
        const bool color_applied = SetSysColors(1, &element, &color) != FALSE;

        const bool wallpaper_cleared = SystemParametersInfoW(
            SPI_SETDESKWALLPAPER, 0, const_cast<wchar_t*>(L""), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE) != FALSE;

        return report(
            color_result == ERROR_SUCCESS && color_applied && wallpaper_cleared,
            L"Desktop background set to solid black.",
            L"Failed to set the desktop background to solid black.");
    }

    bool set_accent_palette() {
        const LONG result = RegSetKeyValueW(
            HKEY_CURRENT_USER,
            accent_key,
            L"AccentPalette",
            REG_BINARY,
            overcast_palette,
            sizeof(overcast_palette));

        return report(
            result == ERROR_SUCCESS,
            L"Accent palette set to Overcast.",
            L"Failed to set the accent palette.");
    }

    bool disable_lock_screen_detailed_status() {
        // An empty string is "None" in the lock screen status setting.
        const LONG result = RegSetKeyValueW(
            HKEY_CURRENT_USER,
            lock_screen_key,
            L"DetailedStatusApp",
            REG_SZ,
            L"",
            sizeof(wchar_t));  // the terminating null of the empty string

        return report(
            result == ERROR_SUCCESS,
            L"Lock screen detailed status set to none.",
            L"Failed to set the lock screen detailed status.");
    }

    // Same end state as "Adjust for best performance" in sysdm.cpl, before font smoothing is ticked again.
    bool disable_visual_effects() {
        constexpr UINT flags = SPIF_UPDATEINIFILE | SPIF_SENDCHANGE;
        bool ok = true;

        for (const UINT action : visual_effect_actions) {
            // pvParam carries the BOOL value itself, so nullptr means FALSE.
            ok = SystemParametersInfoW(action, 0, nullptr, flags) != FALSE && ok;
        }

        ANIMATIONINFO animation{ sizeof(animation), 0 };  // iMinAnimate = 0: no minimize/maximize animation
        ok = SystemParametersInfoW(SPI_SETANIMATION, sizeof(animation), &animation, flags) != FALSE && ok;
        ok = SystemParametersInfoW(SPI_SETDRAGFULLWINDOWS, FALSE, nullptr, flags) != FALSE && ok;
        ok = apply_settings(visual_effect_settings) && ok;

        return report(
            ok,
            L"Visual effects set to best performance.",
            L"Failed to set every visual effect to best performance.");
    }

    // "Smooth edges of screen fonts", with ClearType as the smoothing type.
    bool enable_font_smoothing() {
        constexpr UINT flags = SPIF_UPDATEINIFILE | SPIF_SENDCHANGE;

        bool ok = SystemParametersInfoW(SPI_SETFONTSMOOTHING, TRUE, nullptr, flags) != FALSE;
        ok = SystemParametersInfoW(
            SPI_SETFONTSMOOTHINGTYPE,
            0,
            reinterpret_cast<PVOID>(static_cast<UINT_PTR>(FE_FONTSMOOTHINGCLEARTYPE)),
            flags) != FALSE && ok;

        return report(
            ok,
            L"Smooth edges of screen fonts enabled.",
            L"Failed to enable smooth edges of screen fonts.");
    }

    bool enable_taskbar_autohide() {
        BYTE data[256] = {};
        DWORD size = sizeof(data);
        LONG result = RegGetValueW(HKEY_CURRENT_USER, stuck_rects_key, L"Settings", RRF_RT_REG_BINARY, nullptr, data, &size);

        if (result == ERROR_SUCCESS && size > 8) {
            data[8] |= autohide_flag;
            result = RegSetKeyValueW(HKEY_CURRENT_USER, stuck_rects_key, L"Settings", REG_BINARY, data, size);
        }
        else if (result == ERROR_SUCCESS) {
            result = ERROR_INVALID_DATA;
        }

        return report(
            result == ERROR_SUCCESS,
            L"Taskbar auto-hide enabled.",
            L"Failed to enable taskbar auto-hide.");
    }

    void broadcast_setting_change(const wchar_t* area) {
        SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, reinterpret_cast<LPARAM>(area), SMTO_ABORTIFHUNG, 5000, nullptr);
    }

    bool set_expand_string(HKEY root, const wchar_t* sub_key, const wchar_t* name, const wchar_t* value) {
        const DWORD size = static_cast<DWORD>((std::wcslen(value) + 1) * sizeof(wchar_t));
        const LONG result = RegSetKeyValueW(root, sub_key, name, REG_EXPAND_SZ, value, size);

        if (result != ERROR_SUCCESS) {
            std::wcerr << L"failed to set " << name << L" (error " << result << L")\n";
            return false;
        }
        return true;
    }

    bool setup_temp_directory_and_variables() {
        std::error_code ec;
        fs::create_directories(temp_dir, ec);
        if (ec) {
            std::wcerr << L"failed to create " << temp_dir << L" (error " << ec.value() << L")\n";
            return false;
        }

        bool ok = true;
        for (const wchar_t* name : temp_variables) {
            ok = set_expand_string(HKEY_CURRENT_USER, user_environment_key, name, temp_dir) && ok;
            // Child processes inherit this process's environment, including the explorer.exe
            // restart later in this run, so update it too or explorer comes back with the old TEMP.
            ok = SetEnvironmentVariableW(name, temp_dir) != FALSE && ok;
        }

        if (is_elevated()) {
            for (const wchar_t* name : temp_variables) {
                ok = set_expand_string(HKEY_LOCAL_MACHINE, system_environment_key, name, temp_dir) && ok;
            }
        }
        else {
            std::wcerr << L"system TEMP and TMP skipped, run as administrator\n";
            ok = false;
        }

        broadcast_setting_change(L"Environment");
        return report(
            ok,
            L"User and system TEMP and TMP set to C:\\TEMP.",
            L"Failed to set TEMP and TMP to C:\\TEMP.");
    }

    bool unpin_everything_from_taskbar() {
        const fs::path pinned_folder = get_taskbar_pinned_folder_path();

        bool ok = !pinned_folder.empty() && report(
            clear_folder(pinned_folder),
            L"Taskbar shortcuts folder cleared.",
            L"Failed to clear the taskbar shortcuts folder.");

        ok = report(
            delete_taskband_registry_key(),
            L"Taskband registry key deleted.",
            L"Failed to delete the Taskband registry key.") && ok;

        restart_explorer();
        return ok;
    }

}  // namespace

int main() {
    bool ok = true;
    ok = apply_settings(interface_settings) && ok;
    ok = apply_settings(system_settings) && ok;
    ok = setup_temp_directory_and_variables() && ok;
    ok = apply_settings(personalization_settings) && ok;
    ok = set_accent_palette() && ok;
    ok = disable_lock_screen_detailed_status() && ok;
    ok = disable_visual_effects() && ok;
    ok = enable_font_smoothing() && ok;
    broadcast_setting_change(L"ImmersiveColorSet");
    ok = set_black_desktop_background() && ok;
    ok = enable_taskbar_autohide() && ok;
    ok = apply_settings(telemetry_settings) && ok;
    ok = disable_telemetry_services() && ok;
    ok = disable_telemetry_tasks() && ok;
    ok = disable_onedrive_startup() && ok;
    ok = setup_power_plan() && ok;
    ok = disable_screen_sleep() && ok;
    ok = unpin_everything_from_taskbar() && ok;
    system("pause");
    return ok ? 0 : 1;
}
