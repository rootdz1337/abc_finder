#define UNICODE
#define _UNICODE

#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <softpub.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <set>
#include <algorithm>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// Control IDs
// ---------------------------------------------------------------------------
#define IDC_LISTVIEW     1001
#define IDC_SCAN         1002
#define IDC_STATUS       1003
#define IDC_FILTER       1004
#define IDC_FILTER_LBL   1005
#define IDC_DETAILS      1006
#define IDC_CAT_ALL      1010
#define IDC_CAT_A        1011
#define IDC_CAT_B        1012
#define IDC_CAT_C        1013
#define IDC_COPY         1020
#define IDC_OPEN         1021
#define IDC_EXPORT       1022

const wchar_t* WINDOW_CLASS = L"ABCFinderWindow";

HWND g_hWnd       = nullptr;
HWND g_hListView  = nullptr;
HWND g_hScanBtn   = nullptr;
HWND g_hStatus    = nullptr;
HWND g_hFilter    = nullptr;
HWND g_hFilterLbl = nullptr;
HWND g_hDetails   = nullptr;
HWND g_hCopyBtn   = nullptr;
HWND g_hOpenBtn   = nullptr;
HWND g_hExportBtn = nullptr;
HWND g_hCatAll    = nullptr;
HWND g_hCatA      = nullptr;
HWND g_hCatB      = nullptr;
HWND g_hCatC      = nullptr;

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------
struct Finding {
    wchar_t category;      // 'A', 'B', or 'C'
    std::wstring location; // where it lives (registry path / folder)
    std::wstring name;     // item name
    std::wstring value;    // command / path / DLL / etc.
    int score;             // heuristic score (higher = more suspicious)
    std::wstring reason;   // why it was flagged
};

std::vector<Finding> g_allFindings;
wchar_t g_currentCat = L'A'; // 'A','B','C', or 0 = all

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
std::wstring ToLower(const std::wstring& s) {
    std::wstring r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::towlower);
    return r;
}

bool Contains(const std::wstring& hay, const std::wstring& needle) {
    return ToLower(hay).find(ToLower(needle)) != std::wstring::npos;
}

bool FileExists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

// Extract the executable path from a command line
std::wstring ExtractExe(const std::wstring& cmd) {
    if (cmd.empty()) return L"";
    std::wstring s = cmd;
    // Trim
    while (!s.empty() && (s.front() == L' ' || s.front() == L'\t')) s.erase(s.begin());
    while (!s.empty() && (s.back()  == L' ' || s.back()  == L'\t')) s.pop_back();

    if (s.size() >= 2 && s.front() == L'"') {
        size_t e = s.find(L'"', 1);
        if (e != std::wstring::npos) return s.substr(1, e - 1);
    }
    // First token before space
    size_t sp = s.find(L' ');
    if (sp != std::wstring::npos) return s.substr(0, sp);
    return s;
}

// Expand %VAR% and environment strings
std::wstring Expand(const std::wstring& in) {
    wchar_t buf[4096];
    DWORD n = ExpandEnvironmentStringsW(in.c_str(), buf, 4096);
    if (n && n < 4096) return buf;
    return in;
}

// Check whether the file is signed by a trusted publisher
bool IsSigned(const std::wstring& path) {
    if (path.empty() || !FileExists(path)) return false;

    WINTRUST_FILE_INFO fi = { 0 };
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path.c_str();

    WINTRUST_DATA wd = { 0 };
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(NULL, &policy, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy, &wd);

    return status == ERROR_SUCCESS;
}

// Quick suspicious-path heuristic
int ScorePath(const std::wstring& rawPath, const std::wstring& reasonPrefix,
              std::wstring& reasonOut) {
    int score = 0;
    std::wstring path = Expand(rawPath);

    if (path.empty()) return 0;

    // Missing file
    std::wstring exe = ExtractExe(path);
    if (!exe.empty() && !FileExists(exe) &&
        !Contains(exe, L"rundll32") && !Contains(exe, L"mshta") &&
        !Contains(exe, L"cmd") && !Contains(exe, L"powershell")) {
        score += 30;
        reasonOut += reasonPrefix + L" file missing; ";
    }

    // Unsigned
    if (!exe.empty() && FileExists(exe) && !IsSigned(exe)) {
        score += 25;
        reasonOut += reasonPrefix + L" unsigned; ";
    }

    // Suspicious locations
    std::wstring lp = ToLower(path);
    if (lp.find(L"\\appdata\\") != std::wstring::npos ||
        lp.find(L"\\temp\\") != std::wstring::npos ||
        lp.find(L"\\tmp\\") != std::wstring::npos ||
        lp.find(L"\\downloads\\") != std::wstring::npos ||
        lp.find(L"\\public\\") != std::wstring::npos) {
        score += 20;
        reasonOut += reasonPrefix + L" user-writable path; ";
    }

    // Suspicious extensions / LOLBins
    if (lp.find(L".vbs")  != std::wstring::npos ||
        lp.find(L".js")   != std::wstring::npos ||
        lp.find(L".jse")  != std::wstring::npos ||
        lp.find(L".wsf")  != std::wstring::npos ||
        lp.find(L".hta")  != std::wstring::npos ||
        lp.find(L".scr")  != std::wstring::npos ||
        lp.find(L".pif")  != std::wstring::npos) {
        score += 25;
        reasonOut += reasonPrefix + L" script extension; ";
    }

    if (lp.find(L"powershell") != std::wstring::npos ||
        lp.find(L"mshta")      != std::wstring::npos ||
        lp.find(L"rundll32")   != std::wstring::npos ||
        lp.find(L"regsvr32")   != std::wstring::npos ||
        lp.find(L"wscript")    != std::wstring::npos ||
        lp.find(L"cscript")    != std::wstring::npos ||
        lp.find(L"certutil")   != std::wstring::npos ||
        lp.find(L"bitsadmin")  != std::wstring::npos) {
        score += 15;
        reasonOut += reasonPrefix + L" LOLBin; ";
    }

    if (lp.find(L"-enc") != std::wstring::npos ||
        lp.find(L"-encodedcommand") != std::wstring::npos ||
        lp.find(L"frombase64string") != std::wstring::npos ||
        lp.find(L"downloadstring") != std::wstring::npos ||
        lp.find(L"iex(") != std::wstring::npos) {
        score += 35;
        reasonOut += reasonPrefix + L" encoded/obfuscated; ";
    }

    return score;
}

// ---------------------------------------------------------------------------
// REGISTRY helpers
// ---------------------------------------------------------------------------
void ScanRunKey(HKEY root, const std::wstring& subkey, const std::wstring& label) {
    HKEY hKey;
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    DWORD idx = 0;
    wchar_t name[512];
    BYTE data[8192];
    DWORD nameLen, dataLen, type;

    while (true) {
        nameLen = 512;
        dataLen = sizeof(data);
        LONG r = RegEnumValueW(hKey, idx++, name, &nameLen, NULL, &type,
                               data, &dataLen);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;

        std::wstring value;
        if (type == REG_SZ || type == REG_EXPAND_SZ)
            value = (wchar_t*)data;
        else if (type == REG_MULTI_SZ) {
            wchar_t* p = (wchar_t*)data;
            while (*p) { value += p; value += L" "; p += wcslen(p) + 1; }
        } else {
            continue;
        }

        Finding f;
        f.category = L'A';
        f.location = label;
        f.name = name;
        f.value = value;
        f.score = ScorePath(value, L"", f.reason);
        if (f.score > 0)
            g_allFindings.push_back(f);
    }
    RegCloseKey(hKey);
}

void ScanStartupFolder() {
    wchar_t path[MAX_PATH];
    // User startup
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_STARTUP, NULL, 0, path))) {
        std::wstring search = std::wstring(path) + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(search.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (fd.cFileName[0] == L'.') continue;
                Finding f;
                f.category = L'A';
                f.location = L"Startup (User)";
                f.name = fd.cFileName;
                f.value = std::wstring(path) + L"\\" + fd.cFileName;
                f.score = 15;
                f.reason = L"startup item; ";
                if (Contains(fd.cFileName, L".lnk")) {
                    f.score += 5;
                    f.reason += L"shortcut; ";
                }
                g_allFindings.push_back(f);
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
    }
    // Common startup
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_STARTUP, NULL, 0, path))) {
        std::wstring search = std::wstring(path) + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(search.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (fd.cFileName[0] == L'.') continue;
                Finding f;
                f.category = L'A';
                f.location = L"Startup (Common)";
                f.name = fd.cFileName;
                f.value = std::wstring(path) + L"\\" + fd.cFileName;
                f.score = 15;
                f.reason = L"startup item; ";
                g_allFindings.push_back(f);
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
    }
}

void ScanIFEO() {
    // Image File Execution Options — debugger hijack
    std::wstring base = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    HKEY hRoot;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0, KEY_READ, &hRoot) != ERROR_SUCCESS)
        return;

    DWORD i = 0;
    wchar_t sub[512];
    DWORD subLen;
    while (true) {
        subLen = 512;
        if (RegEnumKeyExW(hRoot, i++, sub, &subLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;

        std::wstring dbgKey = base + L"\\" + sub;
        HKEY hSub;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, dbgKey.c_str(), 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            wchar_t dbg[1024] = { 0 };
            DWORD sz = sizeof(dbg), type;
            if (RegQueryValueExW(hSub, L"Debugger", NULL, &type, (BYTE*)dbg, &sz) == ERROR_SUCCESS) {
                Finding f;
                f.category = L'A';
                f.location = L"IFEO\\" + std::wstring(sub);
                f.name = L"Debugger";
                f.value = dbg;
                f.score = 40;
                f.reason = L"IFEO debugger hijack; ";
                f.score += ScorePath(dbg, L"", f.reason);
                g_allFindings.push_back(f);
            }
            RegCloseKey(hSub);
        }
    }
    RegCloseKey(hRoot);
}

void ScanAppInit() {
    // AppInit_DLLs — classic injection point
    const wchar_t* paths[] = {
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
    };
    for (auto p : paths) {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, p, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            continue;

        wchar_t dlls[4096] = { 0 };
        DWORD sz = sizeof(dlls), type;
        if (RegQueryValueExW(hKey, L"AppInit_DLLs", NULL, &type, (BYTE*)dlls, &sz) == ERROR_SUCCESS
            && dlls[0]) {
            Finding f;
            f.category = L'A';
            f.location = p;
            f.name = L"AppInit_DLLs";
            f.value = dlls;
            f.score = 45;
            f.reason = L"AppInit_DLLs injection; ";
            f.score += ScorePath(dlls, L"", f.reason);
            g_allFindings.push_back(f);
        }
        RegCloseKey(hKey);
    }
}

void ScanWinlogon() {
    const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;
    const wchar_t* names[] = { L"Shell", L"Userinit", L"Taskman", L"VmApplet" };
    for (auto n : names) {
        wchar_t buf[2048] = { 0 };
        DWORD sz = sizeof(buf), type;
        if (RegQueryValueExW(hKey, n, NULL, &type, (BYTE*)buf, &sz) == ERROR_SUCCESS && buf[0]) {
            Finding f;
            f.category = L'A';
            f.location = L"Winlogon";
            f.name = n;
            f.value = buf;
            f.score = 20;
            f.reason = L"Winlogon persistence; ";
            f.score += ScorePath(buf, L"", f.reason);
            g_allFindings.push_back(f);
        }
    }
    RegCloseKey(hKey);
}

void ScanComHijacks() {
    // HKCU\Software\Classes\CLSID\{...}\InprocServer32 pointing to user-writable path
    std::wstring base = L"Software\\Classes\\CLSID";
    HKEY hRoot;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, base.c_str(), 0, KEY_READ, &hRoot) != ERROR_SUCCESS)
        return;

    DWORD i = 0;
    wchar_t clsid[128];
    DWORD clsidLen;
    while (true) {
        clsidLen = 128;
        if (RegEnumKeyExW(hRoot, i++, clsid, &clsidLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;

        std::wstring ipKey = base + L"\\" + clsid + L"\\InprocServer32";
        HKEY hSub;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, ipKey.c_str(), 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            wchar_t dll[MAX_PATH * 2] = { 0 };
            DWORD sz = sizeof(dll), type;
            if (RegQueryValueExW(hSub, NULL, NULL, &type, (BYTE*)dll, &sz) == ERROR_SUCCESS && dll[0]) {
                Finding f;
                f.category = L'A';
                f.location = L"HKCU\\Software\\Classes\\CLSID\\" + std::wstring(clsid);
                f.name = L"InprocServer32";
                f.value = dll;
                f.score = 35;
                f.reason = L"HKCU COM hijack; ";
                f.score += ScorePath(dll, L"", f.reason);
                g_allFindings.push_back(f);
            }
            RegCloseKey(hSub);
        }
    }
    RegCloseKey(hRoot);
}

// ---------------------------------------------------------------------------
// BROWSER scanners
// ---------------------------------------------------------------------------
void ScanChromeExtensions(const std::wstring& basePath, const std::wstring& browserName) {
    std::wstring extDir = basePath + L"\\Extensions";
    std::wstring search = extDir + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == L'.' || !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;
        Finding f;
        f.category = L'B';
        f.location = browserName + L" Extensions";
        f.name = fd.cFileName;
        f.value = extDir + L"\\" + fd.cFileName;
        f.score = 10;
        f.reason = L"browser extension; ";
        g_allFindings.push_back(f);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

void ScanBrowsers() {
    wchar_t localAppData[MAX_PATH], appData[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData);

    // Chrome
    ScanChromeExtensions(std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default",
                         L"Chrome");
    // Edge
    ScanChromeExtensions(std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default",
                         L"Edge");
    // Brave
    ScanChromeExtensions(std::wstring(localAppData) + L"\\BraveSoftware\\Brave-Browser\\User Data\\Default",
                         L"Brave");

    // Firefox profiles
    std::wstring ffBase = std::wstring(appData) + L"\\Mozilla\\Firefox\\Profiles";
    std::wstring search = ffBase + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(search.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (fd.cFileName[0] == L'.' || !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                continue;
            std::wstring extDir = ffBase + L"\\" + fd.cFileName + L"\\extensions";
            std::wstring es = extDir + L"\\*";
            WIN32_FIND_DATAW efd;
            HANDLE eh = FindFirstFileW(es.c_str(), &efd);
            if (eh != INVALID_HANDLE_VALUE) {
                do {
                    if (efd.cFileName[0] == L'.') continue;
                    Finding f;
                    f.category = L'B';
                    f.location = L"Firefox Extensions";
                    f.name = efd.cFileName;
                    f.value = extDir + L"\\" + efd.cFileName;
                    f.score = 10;
                    f.reason = L"browser extension; ";
                    g_allFindings.push_back(f);
                } while (FindNextFileW(eh, &efd));
                FindClose(eh);
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
}

// ---------------------------------------------------------------------------
// SERVICES / DRIVERS
// ---------------------------------------------------------------------------
void ScanServices() {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return;

    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, NULL, 0, &needed, &count, &resume, NULL);
    std::vector<BYTE> buf(needed);
    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                               SERVICE_STATE_ALL, buf.data(), (DWORD)buf.size(),
                               &needed, &count, &resume, NULL)) {
        CloseServiceHandle(hSCM);
        return;
    }

    auto* svc = (ENUM_SERVICE_STATUS_PROCESSW*)buf.data();
    for (DWORD i = 0; i < count; ++i) {
        SC_HANDLE hSvc = OpenServiceW(hSCM, svc[i].lpServiceName,
                                      SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;

        DWORD cfgSize = 0;
        QueryServiceConfigW(hSvc, NULL, 0, &cfgSize);
        std::vector<BYTE> cfgBuf(cfgSize);
        auto* cfg = (QUERY_SERVICE_CONFIGW*)cfgBuf.data();
        if (QueryServiceConfigW(hSvc, cfg, cfgSize, &cfgSize)) {
            std::wstring path = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"";
            std::wstring name = svc[i].lpServiceName;
            std::wstring disp = svc[i].lpDisplayName ? svc[i].lpDisplayName : L"";

            Finding f;
            f.category = L'C';
            f.location = L"Service";
            f.name = name + L" (" + disp + L")";
            f.value = path;
            f.score = 0;
            f.reason = L"";

            // Skip Microsoft-signed system32 services unless clearly off
            std::wstring lp = ToLower(path);
            if (lp.find(L"\\windows\\system32\\") != std::wstring::npos &&
                (lp.find(L".exe") != std::wstring::npos)) {
                // Still scan but with lower baseline
                f.score = 0;
            }

            f.score += ScorePath(path, L"", f.reason);

            // Non-system32 path
            if (lp.find(L"\\windows\\system32\\") == std::wstring::npos &&
                lp.find(L"\\windows\\syswow64\\") == std::wstring::npos &&
                !path.empty()) {
                if (lp.find(L"\\program files") == std::wstring::npos) {
                    f.score += 15;
                    f.reason += L"non-standard service path; ";
                }
            }

            if (f.score > 0) g_allFindings.push_back(f);
        }
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSCM);
}

// ---------------------------------------------------------------------------
// SCHEDULED TASKS
// ---------------------------------------------------------------------------
void ScanTasks() {
    // Use schtasks output parsing as a simple approach
    wchar_t temp[MAX_PATH];
    GetTempPathW(MAX_PATH, temp);
    std::wstring outFile = std::wstring(temp) + L"abc_tasks.txt";

    std::wstring cmd = L"cmd.exe /c schtasks /query /fo CSV /v > \"" + outFile + L"\"";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    HANDLE hFile = CreateFileW(outFile.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD sz = GetFileSize(hFile, NULL);
    std::vector<char> data(sz + 1, 0);
    DWORD read = 0;
    ReadFile(hFile, data.data(), sz, &read, NULL);
    CloseHandle(hFile);
    DeleteFileW(outFile.c_str());

    // Split into lines
    std::string content(data.data(), read);
    std::wstring wcontent;
    int wlen = MultiByteToWideChar(CP_ACP, 0, content.c_str(), (int)content.size(),
                                   NULL, 0);
    wcontent.resize(wlen);
    MultiByteToWideChar(CP_ACP, 0, content.c_str(), (int)content.size(),
                        &wcontent[0], wlen);

    size_t pos = 0;
    bool firstLine = true;
    while (pos < wcontent.size()) {
        size_t eol = wcontent.find(L'\n', pos);
        if (eol == std::wstring::npos) eol = wcontent.size();
        std::wstring line = wcontent.substr(pos, eol - pos);
        pos = eol + 1;

        if (firstLine) { firstLine = false; continue; }
        if (line.size() < 5) continue;

        // Naive CSV parse
        std::vector<std::wstring> cols;
        std::wstring cur;
        bool inQuote = false;
        for (wchar_t c : line) {
            if (c == L'"') { inQuote = !inQuote; }
            else if (c == L',' && !inQuote) { cols.push_back(cur); cur.clear(); }
            else cur += c;
        }
        cols.push_back(cur);

        if (cols.size() < 9) continue;
        std::wstring taskName = cols[1];
        std::wstring action   = cols[8];

        Finding f;
        f.category = L'C';
        f.location = L"Scheduled Task";
        f.name = taskName;
        f.value = action;
        f.score = 0;
        f.reason = L"";
        f.score += ScorePath(action, L"", f.reason);
        if (f.score > 0) g_allFindings.push_back(f);
    }
}

// ---------------------------------------------------------------------------
// WMI EVENT SUBSCRIPTIONS (fileless persistence)
// ---------------------------------------------------------------------------
void ScanWmiSubscriptions() {
    // Query root\subscription for __EventFilter and __EventConsumer
    // Use a simple COM query similar to the antivirus example
    // (Kept minimal here — full WMI parsing would add a lot of code.)
    // We'll shell out to PowerShell to enumerate.
    wchar_t temp[MAX_PATH];
    GetTempPathW(MAX_PATH, temp);
    std::wstring outFile = std::wstring(temp) + L"abc_wmi.txt";
    std::wstring cmd =
        L"powershell.exe -NoProfile -Command \"Get-WmiObject -Namespace root\\subscription "
        L"-Class __EventFilter | Select-Object Name,Query | Out-File -Encoding UTF8 '"
        + outFile + L"'\"";

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    HANDLE hFile = CreateFileW(outFile.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    DWORD sz = GetFileSize(hFile, NULL);
    std::vector<char> data(sz + 1, 0);
    DWORD read = 0;
    ReadFile(hFile, data.data(), sz, &read, NULL);
    CloseHandle(hFile);
    DeleteFileW(outFile.c_str());

    std::string content(data.data(), read);
    if (content.empty()) return;

    int wlen = MultiByteToWideChar(CP_UTF8, 0, content.c_str(), (int)content.size(),
                                   NULL, 0);
    std::wstring wcontent(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, content.c_str(), (int)content.size(),
                        &wcontent[0], wlen);

    Finding f;
    f.category = L'C';
    f.location = L"WMI Subscription";
    f.name = L"__EventFilter";
    f.value = wcontent.substr(0, 4000);
    f.score = 30;
    f.reason = L"WMI event subscription present; ";
    g_allFindings.push_back(f);
}

// ---------------------------------------------------------------------------
// Master scan
// ---------------------------------------------------------------------------
void RunFullScan() {
    g_allFindings.clear();
    SetWindowTextW(g_hStatus, L"Scanning autoruns...");
    UpdateWindow(g_hStatus);

    // --- A: Autoruns ---
    ScanRunKey(HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",     L"HKCU\\Run");
    ScanRunKey(HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKCU\\RunOnce");
    ScanRunKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",     L"HKLM\\Run");
    ScanRunKey(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKLM\\RunOnce");
    ScanRunKey(HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",     L"HKLM\\Run (WOW64)");
    ScanRunKey(HKEY_LOCAL_MACHINE, L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKLM\\RunOnce (WOW64)");
    ScanStartupFolder();
    ScanIFEO();
    ScanAppInit();
    ScanWinlogon();
    ScanComHijacks();

    SetWindowTextW(g_hStatus, L"Scanning browsers...");
    UpdateWindow(g_hStatus);
    ScanBrowsers();

    SetWindowTextW(g_hStatus, L"Scanning services...");
    UpdateWindow(g_hStatus);
    ScanServices();

    SetWindowTextW(g_hStatus, L"Scanning scheduled tasks...");
    UpdateWindow(g_hStatus);
    ScanTasks();

    SetWindowTextW(g_hStatus, L"Scanning WMI subscriptions...");
    UpdateWindow(g_hStatus);
    ScanWmiSubscriptions();

    // Sort by score descending
    std::sort(g_allFindings.begin(), g_allFindings.end(),
              [](const Finding& a, const Finding& b) { return a.score > b.score; });

    SetWindowTextW(g_hStatus, L"Scan complete.");
}

// ---------------------------------------------------------------------------
// ListView rendering
// ---------------------------------------------------------------------------
void SetupListView(HWND hList) {
    ListView_SetExtendedListViewStyle(hList,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    LVCOLUMN lvc = { 0 };
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

    struct { const wchar_t* t; int w; } cols[] = {
        { L"Cat",      50 },
        { L"Score",    60 },
        { L"Location", 180 },
        { L"Name",     260 },
        { L"Value",    420 },
        { L"Reason",   280 },
    };
    for (int i = 0; i < 6; ++i) {
        lvc.iSubItem = i;
        lvc.pszText = (LPWSTR)cols[i].t;
        lvc.cx = cols[i].w;
        ListView_InsertColumn(hList, i, &lvc);
    }
}

void PopulateList() {
    ListView_DeleteAllItems(g_hListView);

    wchar_t filterBuf[256] = { 0 };
    GetWindowTextW(g_hFilter, filterBuf, 256);
    std::wstring filter = ToLower(filterBuf);

    int row = 0;
    for (const auto& f : g_allFindings) {
        if (g_currentCat != 0 && f.category != g_currentCat) continue;
        if (!filter.empty()) {
            std::wstring blob = ToLower(f.location + L" " + f.name + L" " +
                                        f.value + L" " + f.reason);
            if (blob.find(filter) == std::wstring::npos) continue;
        }

        LVITEM lvi = { 0 };
        lvi.mask = LVIF_TEXT;
        lvi.iItem = row;
        lvi.iSubItem = 0;

        wchar_t cat[8] = { f.category, 0 };
        lvi.pszText = cat;
        int r = ListView_InsertItem(g_hListView, &lvi);

        wchar_t sc[16];
        swprintf(sc, 16, L"%d", f.score);
        ListView_SetItemText(g_hListView, r, 1, sc);
        ListView_SetItemText(g_hListView, r, 2, (LPWSTR)f.location.c_str());
        ListView_SetItemText(g_hListView, r, 3, (LPWSTR)f.name.c_str());
        ListView_SetItemText(g_hListView, r, 4, (LPWSTR)f.value.c_str());
        ListView_SetItemText(g_hListView, r, 5, (LPWSTR)f.reason.c_str());

        // Red tint for high-score rows
        if (f.score >= 50) {
            ListView_SetItemText(g_hListView, r, 4, (LPWSTR)f.value.c_str());
        }
        row++;
    }

    wchar_t status[128];
    swprintf(status, 128, L"Showing %d of %zu finding(s).",
             row, g_allFindings.size());
    SetWindowTextW(g_hStatus, status);
}

void ShowSelectedDetails() {
    int sel = ListView_GetNextItem(g_hListView, -1, LVNI_SELECTED);
    if (sel < 0) { SetWindowTextW(g_hDetails, L"(no selection)"); return; }

    wchar_t cat[8] = { 0 }, sc[16] = { 0 }, loc[512] = { 0 },
           name[512] = { 0 }, val[2048] = { 0 }, reason[1024] = { 0 };
    ListView_GetItemText(g_hListView, sel, 0, cat, 8);
    ListView_GetItemText(g_hListView, sel, 1, sc, 16);
    ListView_GetItemText(g_hListView, sel, 2, loc, 512);
    ListView_GetItemText(g_hListView, sel, 3, name, 512);
    ListView_GetItemText(g_hListView, sel, 4, val, 2048);
    ListView_GetItemText(g_hListView, sel, 5, reason, 1024);

    wchar_t buf[4096];
    swprintf(buf, 4096,
        L"Category: %s   Score: %s\r\n"
        L"Location: %s\r\n"
        L"Name:     %s\r\n"
        L"Value:    %s\r\n"
        L"Reason:   %s",
        cat, sc, loc, name, val, reason);
    SetWindowTextW(g_hDetails, buf);
}

// ---------------------------------------------------------------------------
// Export results to CSV
// ---------------------------------------------------------------------------
void ExportCsv() {
    wchar_t path[MAX_PATH] = L"abc_findings.csv";
    OPENFILENAMEW ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hWnd;
    ofn.lpstrFilter = L"CSV Files\0*.csv\0All Files\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"csv";

    if (!GetSaveFileNameW(&ofn)) return;

    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        MessageBoxW(g_hWnd, L"Failed to create file.", L"Export", MB_OK | MB_ICONERROR);
        return;
    }

    auto WriteStr = [&](const std::wstring& s) {
        DWORD w = 0;
        WriteFile(hFile, s.c_str(), (DWORD)(s.size() * sizeof(wchar_t)), &w, NULL);
    };

    // UTF-16 LE BOM
    WORD bom = 0xFEFF;
    DWORD w = 0;
    WriteFile(hFile, &bom, 2, &w, NULL);

    WriteStr(L"Category,Score,Location,Name,Value,Reason\r\n");

    auto CsvEsc = [](const std::wstring& s) -> std::wstring {
        bool needQuote = s.find(L',') != std::wstring::npos ||
                         s.find(L'"') != std::wstring::npos ||
                         s.find(L'\n') != std::wstring::npos ||
                         s.find(L'\r') != std::wstring::npos;
        if (!needQuote) return s;
        std::wstring r = L"\"";
        for (wchar_t c : s) { if (c == L'"') r += L"\""; r += c; }
        r += L"\"";
        return r;
    };

    for (const auto& f : g_allFindings) {
        if (g_currentCat != 0 && f.category != g_currentCat) continue;
        wchar_t cat[4] = { f.category, 0 };
        std::wstring line;
        line += cat; line += L",";
        wchar_t sc[16]; swprintf(sc, 16, L"%d", f.score);
        line += sc; line += L",";
        line += CsvEsc(f.location); line += L",";
        line += CsvEsc(f.name);     line += L",";
        line += CsvEsc(f.value);    line += L",";
        line += CsvEsc(f.reason);   line += L"\r\n";
        WriteStr(line);
    }

    CloseHandle(hFile);
    MessageBoxW(g_hWnd, L"Exported successfully.", L"Export", MB_OK | MB_ICONINFORMATION);
}

// ---------------------------------------------------------------------------
// Window proc
// ---------------------------------------------------------------------------
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CREATE: {
        HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;

        // Top row
        CreateWindowExW(0, L"STATIC", L"Filter:",
            WS_CHILD | WS_VISIBLE, 10, 14, 50, 22, hWnd, (HMENU)IDC_FILTER_LBL, hInst, NULL);
        g_hFilterLbl = GetDlgItem(hWnd, IDC_FILTER_LBL);

        g_hFilter = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            65, 10, 260, 26, hWnd, (HMENU)IDC_FILTER, hInst, NULL);

        // Category radio buttons
        g_hCatAll = CreateWindowExW(0, L"BUTTON", L"All",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
            340, 12, 50, 22, hWnd, (HMENU)IDC_CAT_ALL, hInst, NULL);
        g_hCatA   = CreateWindowExW(0, L"BUTTON", L"A: Autoruns",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
            395, 12, 100, 22, hWnd, (HMENU)IDC_CAT_A, hInst, NULL);
        g_hCatB   = CreateWindowExW(0, L"BUTTON", L"B: Browser",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
            500, 12, 100, 22, hWnd, (HMENU)IDC_CAT_B, hInst, NULL);
        g_hCatC   = CreateWindowExW(0, L"BUTTON", L"C: Comp/Svc",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
            605, 12, 100, 22, hWnd, (HMENU)IDC_CAT_C, hInst, NULL);
        SendMessage(g_hCatAll, BM_SETCHECK, BST_CHECKED, 0);

        g_hScanBtn = CreateWindowExW(0, L"BUTTON", L"Scan",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            720, 10, 80, 26, hWnd, (HMENU)IDC_SCAN, hInst, NULL);
        g_hExportBtn = CreateWindowExW(0, L"BUTTON", L"Export CSV",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            805, 10, 90, 26, hWnd, (HMENU)IDC_EXPORT, hInst, NULL);

        // ListView
        g_hListView = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
            10, 45, 880, 360, hWnd, (HMENU)IDC_LISTVIEW, hInst, NULL);
        SetupListView(g_hListView);

        // Bottom buttons
        g_hCopyBtn = CreateWindowExW(0, L"BUTTON", L"Copy Value",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, 415, 110, 28, hWnd, (HMENU)IDC_COPY, hInst, NULL);
        g_hOpenBtn = CreateWindowExW(0, L"BUTTON", L"Open Location",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            130, 415, 130, 28, hWnd, (HMENU)IDC_OPEN, hInst, NULL);

        g_hStatus = CreateWindowExW(0, L"STATIC", L"Ready.",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            280, 420, 610, 22, hWnd, (HMENU)IDC_STATUS, hInst, NULL);

        // Details box
        g_hDetails = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT",
            L"(no selection)",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY |
            WS_VSCROLL | ES_AUTOVSCROLL,
            10, 450, 880, 100, hWnd, (HMENU)IDC_DETAILS, hInst, NULL);

        // Fonts
        HFONT hFont = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        EnumChildWindows(hWnd, [](HWND h, LPARAM lp) -> BOOL {
            SendMessage(h, WM_SETFONT, (WPARAM)lp, TRUE);
            return TRUE;
        }, (LPARAM)hFont);

        HFONT hMono = CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
        SendMessage(g_hDetails, WM_SETFONT, (WPARAM)hMono, TRUE);
        return 0;
    }

    case WM_SIZE: {
        RECT rc;
        GetClientRect(hWnd, &rc);
        int m = 10, topH = 26, btnH = 28, detailsH = 100, statusH = 22;
        int listTop = m + topH + 9;
        int listH = rc.bottom - listTop - m - btnH - 8 - detailsH - 8 - statusH - 4;

        SetWindowPos(g_hFilterLbl, NULL, m, m + 4, 50, 22, SWP_NOZORDER);
        SetWindowPos(g_hFilter, NULL, m + 55, m, 260, topH, SWP_NOZORDER);
        SetWindowPos(g_hCatAll, NULL, 340, m + 2, 50, 22, SWP_NOZORDER);
        SetWindowPos(g_hCatA,   NULL, 395, m + 2, 100, 22, SWP_NOZORDER);
        SetWindowPos(g_hCatB,   NULL, 500, m + 2, 100, 22, SWP_NOZORDER);
        SetWindowPos(g_hCatC,   NULL, 605, m + 2, 100, 22, SWP_NOZORDER);
        SetWindowPos(g_hScanBtn, NULL, rc.right - m - 90 - 10 - 80, m, 80, topH, SWP_NOZORDER);
        SetWindowPos(g_hExportBtn, NULL, rc.right - m - 90, m, 90, topH, SWP_NOZORDER);

        SetWindowPos(g_hListView, NULL, m, listTop, rc.right - m * 2, listH, SWP_NOZORDER);

        int btnY = listTop + listH + 8;
        SetWindowPos(g_hCopyBtn, NULL, m, btnY, 110, btnH, SWP_NOZORDER);
        SetWindowPos(g_hOpenBtn, NULL, m + 120, btnY, 130, btnH, SWP_NOZORDER);
        SetWindowPos(g_hStatus, NULL, m + 260, btnY + 4, rc.right - m * 2 - 260, statusH, SWP_NOZORDER);

        int detailsY = btnY + btnH + 8;
        SetWindowPos(g_hDetails, NULL, m, detailsY, rc.right - m * 2, detailsH, SWP_NOZORDER);

        int totalW = rc.right - m * 2;
        if (totalW > 200) {
            int fixed = 50 + 60 + 180 + 260 + 280;
            int valueW = totalW - fixed - 25;
            if (valueW < 150) valueW = 150;
            ListView_SetColumnWidth(g_hListView, 0, 50);
            ListView_SetColumnWidth(g_hListView, 1, 60);
            ListView_SetColumnWidth(g_hListView, 2, 180);
            ListView_SetColumnWidth(g_hListView, 3, 260);
            ListView_SetColumnWidth(g_hListView, 4, valueW);
            ListView_SetColumnWidth(g_hListView, 5, 280);
        }
        return 0;
    }

    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDC_SCAN:
            RunFullScan();
            PopulateList();
            break;

        case IDC_EXPORT:
            ExportCsv();
            break;

        case IDC_FILTER:
            if (HIWORD(wParam) == EN_CHANGE) PopulateList();
            break;

        case IDC_CAT_ALL: g_currentCat = 0;  PopulateList(); break;
        case IDC_CAT_A:   g_currentCat = L'A'; PopulateList(); break;
        case IDC_CAT_B:   g_currentCat = L'B'; PopulateList(); break;
        case IDC_CAT_C:   g_currentCat = L'C'; PopulateList(); break;

        case IDC_COPY: {
            int sel = ListView_GetNextItem(g_hListView, -1, LVNI_SELECTED);
            if (sel < 0) break;
            wchar_t val[2048] = { 0 };
            ListView_GetItemText(g_hListView, sel, 4, val, 2048);
            if (OpenClipboard(hWnd)) {
                EmptyClipboard();
                size_t sz = (wcslen(val) + 1) * sizeof(wchar_t);
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, sz);
                if (hMem) {
                    memcpy(GlobalLock(hMem), val, sz);
                    GlobalUnlock(hMem);
                    SetClipboardData(CF_UNICODETEXT, hMem);
                }
                CloseClipboard();
            }
            break;
        }

        case IDC_OPEN: {
            int sel = ListView_GetNextItem(g_hListView, -1, LVNI_SELECTED);
            if (sel < 0) break;
            wchar_t val[2048] = { 0 };
            ListView_GetItemText(g_hListView, sel, 4, val, 2048);
            std::wstring exe = ExtractExe(val);
            if (!exe.empty()) {
                std::wstring folder = exe;
                size_t p = folder.find_last_of(L'\\');
                if (p != std::wstring::npos) folder = folder.substr(0, p);
                ShellExecuteW(hWnd, L"open", folder.c_str(), NULL, NULL, SW_SHOWNORMAL);
            }
            break;
        }
        }
        return 0;
    }

    case WM_NOTIFY: {
        LPNMHDR lpnmh = (LPNMHDR)lParam;
        if (lpnmh->idFrom == IDC_LISTVIEW) {
            if (lpnmh->code == LVN_ITEMCHANGED) {
                ShowSelectedDetails();
            } else if (lpnmh->code == NM_DBLCLK) {
                ShowSelectedDetails();
            }
        }
        return 0;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icex = { 0 };
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = WINDOW_CLASS;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(NULL, L"Window registration failed.", L"Error",
                    MB_OK | MB_ICONERROR);
        return 1;
    }

    g_hWnd = CreateWindowExW(0, WINDOW_CLASS,
        L"ABC Finder — Autoruns / Browser / Components",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 940, 640,
        NULL, NULL, hInstance, NULL);

    if (!g_hWnd) {
        MessageBoxW(NULL, L"Window creation failed.", L"Error",
                    MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (!IsDialogMessage(g_hWnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return (int)msg.wParam;
}
