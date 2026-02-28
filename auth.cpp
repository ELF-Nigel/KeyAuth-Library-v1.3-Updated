#ifndef UNICODE
#define UNICODE
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define _CRT_SECURE_NO_WARNINGS

#include <auth.hpp>
#include <strsafe.h> 
#include <windows.h>
#include <string>
#include <stdio.h>
#include <iostream>

#include <shellapi.h>

#include <sstream> 
#include <iomanip> 
#include <xorstr.hpp>
#include <fstream> 
#include <http.h>
#include <stdlib.h>
#include <atlstr.h>
#include <bcrypt.h>

#include <ctime>
#include <filesystem>

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "httpapi.lib")
#pragma comment(lib, "bcrypt.lib")

#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

#include <functional>
#include <vector>
#include <bitset>
#include <cstdint>
#include <psapi.h>
#pragma comment( lib, "psapi.lib" )
#include <thread>

#include <cctype>
#include <algorithm>
#include <cstring>
#include <cwctype>

#include "Security.hpp"
#include "killEmulator.hpp"
#include <lazy_importer.hpp>
#include <QRCode/qrcode.hpp>
#include <QRCode/qr.png.h>

#define SHA256_HASH_SIZE 32

static std::string hexDecode(const std::string& hex);
std::string get_str_between_two_str(const std::string& s, const std::string& start_delim, const std::string& stop_delim);
int VerifyPayload(std::string signature, std::string timestamp, std::string body);
void checkInit();
std::string checksum();
void modify();
void runChecks();
void checkAtoms();
void checkFiles();
void checkRegistry();
void error(std::string message);
std::string generate_random_number();
std::string seed;
void cleanUpSeedData(const std::string& seed);
thread_local std::string signature;
thread_local std::string signatureTimestamp;
std::atomic<bool> initialized(false);
std::string API_PUBLIC_KEY = "5586b4bc69c7a4b487e4563a4cd96afd39140f919bd31cea7d1c6a1e8439422b";
bool KeyAuth::api::debug = false;
std::atomic<bool> LoggedIn(false);
static bool is_localhost_host(const wchar_t* host);
static bool is_loopback_addr(const SOCKADDR* addr);
static void send_simple_http_response(HANDLE requestQueueHandle, PHTTP_REQUEST pRequest, USHORT status, const char* reason);

// optional compatibility toggle for injected/DLL use-cases -nigel
static bool allow_injection_compat()
{
#ifdef KEYAUTH_ALLOW_INJECTION
    return true;
#else
    return std::getenv("KEYAUTH_ALLOW_INJECTION") != nullptr;
#endif
}

static void harden_process_defaults()
{
    // harden dll search path and heap corruption behavior without API changes -nigel
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32) {
        auto set_default_dirs = reinterpret_cast<BOOL(WINAPI*)(DWORD)>(
            GetProcAddress(kernel32, "SetDefaultDllDirectories"));
        if (set_default_dirs) {
            set_default_dirs(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS);
        }
        auto set_dll_dir = reinterpret_cast<BOOL(WINAPI*)(LPCWSTR)>(
            GetProcAddress(kernel32, "SetDllDirectoryW"));
        if (set_dll_dir) {
            set_dll_dir(L"");
        }
    }

    HeapSetInformation(GetProcessHeap(), HeapEnableTerminationOnCorruption, nullptr, 0);
}

// Security hardening updates applied in auth.* -nigel
// in-process hashing (no certutil/_popen), stricter transport policy, signed-response checks
// bounded request/response sizes, safer JSON parse behavior, sensitive memory cleanup
// DPAPI seed artifact protection and thread-safety hardening for signature/init state
namespace {
    constexpr ULONGLONG kRequestTimeoutMs = 15000;
    constexpr long long kMaxAllowedClockSkewSeconds = 20;
    constexpr std::size_t kMaxResponseBytes = 1024 * 1024;
    constexpr std::size_t kMaxRequestBytes = 1024 * 1024;

    struct ResponseBuffer {
        std::string body;
        bool overflow = false;
    };

    std::string escape_for_post(CURL* curl, const std::string& value) {
        if (!curl) {
            return value;
        }
        char* escaped = curl_easy_escape(curl, value.c_str(), static_cast<int>(value.size()));
        if (!escaped) {
            return value;
        }
        std::string result(escaped);
        curl_free(escaped);
        return result;
    }

    bool has_https_scheme(const std::string& value) {
        constexpr char kPrefix[] = "https://";
        return value.size() >= (sizeof(kPrefix) - 1) && value.compare(0, sizeof(kPrefix) - 1, kPrefix) == 0;
    }

    // strict URL-format validation helper for transport safety -nigel
    bool is_transport_url_safe(const std::string& url) {
        if (!has_https_scheme(url)) {
            return false;
        }
        if (url.find('#') != std::string::npos || url.find('\\') != std::string::npos) {
            return false;
        }
        if (std::any_of(url.begin(), url.end(), [](unsigned char c) {
            return std::iscntrl(c) != 0 || std::isspace(c) != 0;
        })) {
            return false;
        }

        const std::size_t schemeEnd = url.find("://");
        if (schemeEnd == std::string::npos) {
            return false;
        }

        const std::size_t authorityStart = schemeEnd + 3;
        const std::size_t authorityEnd = url.find_first_of("/?", authorityStart);
        const std::string authority = authorityEnd == std::string::npos
            ? url.substr(authorityStart)
            : url.substr(authorityStart, authorityEnd - authorityStart);
        if (authority.empty() || authority.find('@') != std::string::npos) {
            return false;
        }

        return std::all_of(authority.begin(), authority.end(), [](unsigned char c) {
            return std::isalnum(c) != 0 || c == '.' || c == '-' || c == ':';
        });
    }

    // in-process hashing to avoid certutil/_popen shell execution -nigel
    std::string md5_file_hex(const std::string& filePath) {
        BCRYPT_ALG_HANDLE algHandle = nullptr;
        BCRYPT_HASH_HANDLE hashHandle = nullptr;
        std::vector<unsigned char> hashObject;
        std::vector<unsigned char> hashOutput;
        DWORD objectLength = 0;
        DWORD hashLength = 0;
        DWORD cbResult = 0;

        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return "";
        }

        NTSTATUS status = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_MD5_ALGORITHM, nullptr, 0);
        if (status < 0) {
            return "";
        }

        status = BCryptGetProperty(algHandle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &cbResult, 0);
        if (status < 0 || objectLength == 0) {
            BCryptCloseAlgorithmProvider(algHandle, 0);
            return "";
        }

        status = BCryptGetProperty(algHandle, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &cbResult, 0);
        if (status < 0 || hashLength == 0) {
            BCryptCloseAlgorithmProvider(algHandle, 0);
            return "";
        }

        hashObject.resize(objectLength);
        hashOutput.resize(hashLength);

        status = BCryptCreateHash(algHandle, &hashHandle, hashObject.data(), objectLength, nullptr, 0, 0);
        if (status < 0) {
            BCryptCloseAlgorithmProvider(algHandle, 0);
            return "";
        }

        std::array<char, 8192> buffer{};
        while (file.good()) {
            file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const std::streamsize bytesRead = file.gcount();
            if (bytesRead > 0) {
                status = BCryptHashData(hashHandle, reinterpret_cast<PUCHAR>(buffer.data()), static_cast<ULONG>(bytesRead), 0);
                if (status < 0) {
                    BCryptDestroyHash(hashHandle);
                    BCryptCloseAlgorithmProvider(algHandle, 0);
                    return "";
                }
            }
        }

        status = BCryptFinishHash(hashHandle, hashOutput.data(), hashLength, 0);
        BCryptDestroyHash(hashHandle);
        BCryptCloseAlgorithmProvider(algHandle, 0);
        if (status < 0) {
            return "";
        }

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (unsigned char byte : hashOutput) {
            oss << std::setw(2) << static_cast<int>(byte);
        }

        return oss.str();
    }

    // wipe sensitive strings after use -nigel
    void secure_clear_string(std::string& value) {
        if (!value.empty()) {
            sodium_memzero(value.data(), value.size());
            value.clear();
            value.shrink_to_fit();
        }
    }

    // DPAPI encrypt on-disk seed content -nigel
    bool write_protected_seed_file(const std::string& filePath, const std::string& plaintext) {
        if (plaintext.empty()) {
            return false;
        }

        std::vector<BYTE> plaintextBuffer(plaintext.begin(), plaintext.end());
        DATA_BLOB inputBlob{};
        inputBlob.pbData = plaintextBuffer.data();
        inputBlob.cbData = static_cast<DWORD>(plaintextBuffer.size());

        DATA_BLOB encryptedBlob{};
        if (!CryptProtectData(&inputBlob, L"KeyAuthSeed", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &encryptedBlob)) {
            return false;
        }

        std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            if (encryptedBlob.pbData && encryptedBlob.cbData > 0) {
                SecureZeroMemory(encryptedBlob.pbData, encryptedBlob.cbData);
            }
            if (encryptedBlob.pbData) {
                LocalFree(encryptedBlob.pbData);
            }
            return false;
        }

        file.write(reinterpret_cast<const char*>(encryptedBlob.pbData), static_cast<std::streamsize>(encryptedBlob.cbData));
        file.close();
        const bool ok = file.good();

        // reduce casual discovery of seed artifacts -nigel
        SetFileAttributesA(filePath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);

        if (encryptedBlob.pbData && encryptedBlob.cbData > 0) {
            SecureZeroMemory(encryptedBlob.pbData, encryptedBlob.cbData);
        }
        if (encryptedBlob.pbData) {
            LocalFree(encryptedBlob.pbData);
        }
        if (!plaintextBuffer.empty()) {
            SecureZeroMemory(plaintextBuffer.data(), plaintextBuffer.size());
        }

        return ok;
    }

    // fail-closed JSON parsing helper -nigel
    nlohmann::json parse_json_or_fail(const std::string& raw) {
        auto parsed = nlohmann::json::parse(raw, nullptr, false);
        if (parsed.is_discarded() || !parsed.is_object()) {
            error(XorStr("Invalid server response format."));
        }
        return parsed;
    }

    bool is_decimal_ascii(const std::string& value) {
        if (value.empty()) {
            return false;
        }
        return std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return c >= '0' && c <= '9';
        });
    }

    bool is_hex_ascii(const std::string& value) {
        if (value.empty()) {
            return false;
        }
        return std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return std::isxdigit(c) != 0;
        });
    }
}

void KeyAuth::api::init()
{
    std::thread(runChecks).detach();
    seed = generate_random_number();
    std::atexit([]() { cleanUpSeedData(seed); });
    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)modify, 0, 0, 0);
    if (!allow_injection_compat()) {
        harden_process_defaults();
    }

    if (ownerid.length() != 10)
    {
        MessageBoxA(0, XorStr("Application Not Setup Correctly. Please Watch Video Linked in main.cpp").c_str(), NULL, MB_ICONERROR);
        LI_FN(exit)(0);
    }

    std::string hash = checksum();
    CURL* curl = curl_easy_init();
    std::string encodedName = escape_for_post(curl, name);
    auto data =
        XorStr("type=init") +
        XorStr("&ver=") + version +
        XorStr("&hash=") + hash +
        XorStr("&name=") + encodedName +
        XorStr("&ownerid=") + ownerid;

    // to ensure people removed secret from main.cpp (some people will forget to)
    if (path.find("https") != std::string::npos) {
        MessageBoxA(0, XorStr("You forgot to remove \"secret\" from main.cpp. Copy details from ").c_str(), NULL, MB_ICONERROR);
        LI_FN(exit)(0);
    }

    // honor optional token file path only when explicitly provided -nigel
    if (!path.empty()) {

        if (!std::filesystem::exists(path)) {
            MessageBoxA(0, XorStr("File not found. Please make sure the file exists.").c_str(), NULL, MB_ICONERROR);
            LI_FN(exit)(0);
        }
        // get the contents of the file
        std::ifstream file(path);
        std::string token;
        std::string thash;
        std::getline(file, token);

        thash = md5_file_hex(path);
        if (thash.empty()) {
            MessageBoxA(0, XorStr("Failed to hash token file.").c_str(), NULL, MB_ICONERROR);
            LI_FN(exit)(0);
        }

        data += XorStr("&token=").c_str() + token;
        data += XorStr("&thash=").c_str() + thash;
        secure_clear_string(token);
    }
    curl_easy_cleanup(curl);

    auto response = req(data, url);

    if (response == XorStr("KeyAuth_Invalid").c_str()) {
        MessageBoxA(0, XorStr("Application not found. Please copy strings directly from dashboard.").c_str(), NULL, MB_ICONERROR);
        LI_FN(exit)(0);
    }

    std::hash<int> hasher;
    int expectedHash = hasher(42);

    // 4 lines down, used for debug
    /*std::cout << "[DEBUG] Preparing to verify payload..." << std::endl;
    std::cout << "[DEBUG] Signature: " << signature << std::endl;
    std::cout << "[DEBUG] Timestamp: " << signatureTimestamp << std::endl;
    std::cout << "[DEBUG] Raw body: " << response << std::endl;*/

    if (signature.empty() || signatureTimestamp.empty()) { // used for debug
        std::cerr << "[ERROR] Signature or timestamp is empty. Cannot verify." << std::endl;
        MessageBoxA(0, "Missing signature headers in response", "KeyAuth", MB_ICONERROR);
        exit(99); // Temporary debug exit code
    }


    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = parse_json_or_fail(response);

        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        load_response_data(json);

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            if (json[(XorStr("success"))])
            {
                if (json[(XorStr("newSession"))]) {
                    Sleep(100);
                }
                sessionid = json[(XorStr("sessionid"))];
                initialized.store(true);
                load_app_data(json[(XorStr("appinfo"))]);
            }
            else if (json[(XorStr("message"))] == XorStr("invalidver"))
            {
                std::string dl = json[(XorStr("download"))];
                api::app_data.downloadLink = json[XorStr("download")];
                if (dl == "")
                {
                    MessageBoxA(0, XorStr("Version in the loader does match the one on the dashboard, and the download link on dashboard is blank.\n\nTo fix this, either fix the loader so it matches the version on the dashboard. Or if you intended for it to have different versions, update the download link on dashboard so it will auto-update correctly.").c_str(), NULL, MB_ICONERROR);
                }
                else
                {
                    ShellExecuteA(0, XorStr("open").c_str(), dl.c_str(), 0, 0, SW_SHOWNORMAL);
                }
                LI_FN(exit)(0);
            }
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

// bounded response buffering to avoid unbounded memory growth -nigel
size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    const size_t total = size * nmemb;
    auto* response = static_cast<ResponseBuffer*>(userp);
    if (!response) {
        return 0;
    }

    if (response->body.size() + total > kMaxResponseBytes) {
        response->overflow = true;
        return 0;
    }

    response->body.append(static_cast<char*>(contents), total);
    return total;
}

// Callback function to handle headers
// strict header sanitization for signature metadata -nigel
size_t header_callback(char* buffer, size_t size, size_t nitems, void* userdata) {
    size_t totalSize = size * nitems;

    std::string header(buffer, totalSize);

    // Convert to lowercase for comparison
    std::string lowercase = header;
    std::transform(lowercase.begin(), lowercase.end(), lowercase.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // Signature
    if (lowercase.find("x-signature-ed25519: ") == 0) {
        signature = header.substr(header.find(": ") + 2);
        signature.erase(signature.find_last_not_of("\r\n") + 1);
        if (!is_hex_ascii(signature) || signature.size() != 128) {
            signature.clear();
        }
        //std::cout << "[DEBUG] Captured signature header: " << signature << std::endl;
    }

    // Timestamp
    if (lowercase.find("x-signature-timestamp: ") == 0) {
        signatureTimestamp = header.substr(header.find(": ") + 2);
        signatureTimestamp.erase(signatureTimestamp.find_last_not_of("\r\n") + 1);
        if (!is_decimal_ascii(signatureTimestamp) || signatureTimestamp.size() > 20) {
            signatureTimestamp.clear();
        }
        //std::cout << "[DEBUG] Captured timestamp header: " << signatureTimestamp << std::endl;
    }

    return totalSize;
}


void KeyAuth::api::login(std::string username, std::string password, std::string code)
{
    checkInit();

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=login") +
        XorStr("&username=") + username +
        XorStr("&pass=") + password +
        XorStr("&code=") + code +
        XorStr("&hwid=") + hwid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    secure_clear_string(data);
    secure_clear_string(password);
    secure_clear_string(code);
    //std::cout << "[DEBUG] Login response: " << response << std::endl;
    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = parse_json_or_fail(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        //std::cout << "[DEBUG] Login response:" << response << std::endl;

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
            if (json[(XorStr("success"))])
                load_user_data(json[(XorStr("info"))]);

            if (api::response.message != XorStr("Initialized").c_str()) {
                LI_FN(GlobalAddAtomA)(seed.c_str());

                std::string file_path = XorStr("C:\\ProgramData\\").c_str() + seed;
                if (!write_protected_seed_file(file_path, seed)) {
                    LI_FN(exit)(16);
                }

                std::string regPath = XorStr("Software\\").c_str() + seed;
                HKEY hKey;
                LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
                if (result == ERROR_SUCCESS) {
                    LI_FN(RegSetValueExA)(hKey, seed.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(seed.c_str()), seed.size() + 1);
                    LI_FN(RegCloseKey)(hKey);
                }

                LI_FN(GlobalAddAtomA)(ownerid.c_str());
		LoggedIn.store(true);
            }
            else {
                LI_FN(exit)(12);
            }
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::chatget(std::string channel)
{
    checkInit();

    auto data =
        XorStr("type=chatget") +
        XorStr("&channel=") + channel +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);
    auto json = parse_json_or_fail(response);
    load_channel_data(json);
}

bool KeyAuth::api::chatsend(std::string message, std::string channel)
{
    checkInit();

    auto data =
        XorStr("type=chatsend") +
        XorStr("&message=") + message +
        XorStr("&channel=") + channel +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);
    auto json = parse_json_or_fail(response);
    load_response_data(json);
    return json[("success")];
}

void KeyAuth::api::changeUsername(std::string newusername)
{
    checkInit();

    auto data =
        XorStr("type=changeUsername") +
        XorStr("&newUsername=") + newusername +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);
    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {

        auto json = parse_json_or_fail(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

KeyAuth::api::Tfa& KeyAuth::api::enable2fa(std::string code)
{
    checkInit();

   KeyAuth::api::activate = true;

    auto data =
        XorStr("type=2faenable") +
        XorStr("&code=") + code +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);
    auto json = parse_json_or_fail(response);

    if (json.contains("2fa")) {

        api::response.success = json["success"];
        api::tfa.secret = json["2fa"]["secret_code"];
        api::tfa.link = json["2fa"]["QRCode"];
    }
    else {
        load_response_data(json);
    }
    
    return api::tfa;
}

KeyAuth::api::Tfa& KeyAuth::api::disable2fa(std::string code)
{
    checkInit();
    
    KeyAuth::api::activate = false;

    if (code.empty()) {
        this->tfa.handleInput(*this);
        return api::tfa;
    }


    auto data =
        XorStr("type=2fadisable") +
        XorStr("&code=") + code +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);

    auto json = parse_json_or_fail(response);

    load_response_data(json);

    return api::tfa;
}

void KeyAuth::api::Tfa::QrCode() {
    auto qrcode = QrToPng("QRCode.png", 300, 3, KeyAuth::api::Tfa::link, true, qrcodegen::QrCode::Ecc::MEDIUM);
    qrcode.writeToPNG();
}

void KeyAuth::api::Tfa::handleInput(KeyAuth::api& instance) {

    if (instance.activate) {
        QrCode();

        ShellExecuteA(0, XorStr("open").c_str(), XorStr("QRCode.png").c_str(), 0, 0, SW_SHOWNORMAL);

        system("cls");
        std::cout << XorStr("Press enter when you have scanned the QR code");
        std::cin.get();

        // remove the QR code
        remove("QRCode.png");

        system("cls");

        std::cout << XorStr("Enter the code: ");

        std::string code;
        std::cin >> code;

        instance.enable2fa(code);
    }
    else {

        LI_FN(system)(XorStr("cls").c_str());

        std::cout << XorStr("Enter the code to disable 2FA: ");

		std::string code;
		std::cin >> code;

			instance.disable2fa(code);
		}

    return;
}

void KeyAuth::api::web_login()
{
    checkInit();

    // from https://perpetualprogrammers.wordpress.com/2016/05/22/the-http-server-api/

    // Initialize the API.
    ULONG result = 0;
    HTTPAPI_VERSION version = HTTPAPI_VERSION_2;
    result = HttpInitialize(version, HTTP_INITIALIZE_SERVER, 0);

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "The Flags parameter contains an unsupported value.", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }
    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for Initialize", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    // Create server session.
    HTTP_SERVER_SESSION_ID serverSessionId;
    result = HttpCreateServerSession(version, &serverSessionId, 0);

    if (result == ERROR_REVISION_MISMATCH) {
        MessageBoxA(NULL, "Version for session invalid", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "pServerSessionId parameter is null", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for HttpCreateServerSession", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    // Create URL group.
    HTTP_URL_GROUP_ID groupId;
    result = HttpCreateUrlGroup(serverSessionId, &groupId, 0);

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "Url group create parameter error", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for HttpCreateUrlGroup", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    // Create request queue.
    HANDLE requestQueueHandle;
    result = HttpCreateRequestQueue(version, NULL, NULL, 0, &requestQueueHandle);

    if (result == ERROR_REVISION_MISMATCH) {
        MessageBoxA(NULL, "Wrong version", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "Byte length exceeded", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_ALREADY_EXISTS) {
        MessageBoxA(NULL, "pName already used", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_ACCESS_DENIED) {
        MessageBoxA(NULL, "queue access denied", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_DLL_INIT_FAILED) {
        MessageBoxA(NULL, "Initialize not called", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for HttpCreateRequestQueue", "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    // Attach request queue to URL group.
    HTTP_BINDING_INFO info;
    info.Flags.Present = 1;
    info.RequestQueueHandle = requestQueueHandle;
    result = HttpSetUrlGroupProperty(groupId, HttpServerBindingProperty, &info, sizeof(info));

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, XorStr("Invalid parameter").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, XorStr("System error for HttpSetUrlGroupProperty").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    // Add URLs to URL group.
    PCWSTR url = L"http://localhost:1337/handshake";
    result = HttpAddUrlToUrlGroup(groupId, url, 0, 0);

    if (result == ERROR_ACCESS_DENIED) {
        MessageBoxA(NULL, XorStr("No permissions to run web server").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_ALREADY_EXISTS) {
        MessageBoxA(NULL, XorStr("You are running this program already").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, XorStr("ERROR_INVALID_PARAMETER for HttpAddUrlToUrlGroup").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result == ERROR_SHARING_VIOLATION) {
        MessageBoxA(NULL, XorStr("Another program is using the webserver. Close Razer Chroma mouse software if you use that. Try to restart computer.").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, XorStr("System error for HttpAddUrlToUrlGroup").c_str(), "Error", MB_ICONEXCLAMATION);
        LI_FN(exit)(0);
    }

    // Announce that it is running.
    // wprintf(L"Listening. Please submit requests to: %s\n", url);

    // req to: http://localhost:1337/handshake?user=mak&token=2f3e9eccc22ee583cf7bad86c751d865
    bool going = true;
    while (going == true)
    {
        // Wait for a request.
        HTTP_REQUEST_ID requestId = 0;
        HTTP_SET_NULL_ID(&requestId);
        int bufferSize = 4096;
        int requestSize = sizeof(HTTP_REQUEST) + bufferSize;
        BYTE* buffer = new BYTE[requestSize];
        PHTTP_REQUEST pRequest = (PHTTP_REQUEST)buffer;
        RtlZeroMemory(buffer, requestSize);
        ULONG bytesReturned;
        result = HttpReceiveHttpRequest(
            requestQueueHandle,
            requestId,
            HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY,
            pRequest,
            requestSize,
            &bytesReturned,
            NULL
        );

        // Display some information about the request.
        // wprintf(L"Full URL: %ws\n", pRequest->CookedUrl.pFullUrl);
        // wprintf(L"    Path: %ws\n", pRequest->CookedUrl.pAbsPath);
        // wprintf(L"    Query: %ws\n", pRequest->CookedUrl.pQueryString);

        // std::cout << get_str_between_two_str(CW2A(pRequest->CookedUrl.pQueryString), "?", "&") << std::endl;

        // break if preflight request from browser
        if (pRequest->Verb == HttpVerbOPTIONS)
        {
            // Respond to the request.
            HTTP_RESPONSE response;
            RtlZeroMemory(&response, sizeof(response));

            response.StatusCode = 200;
            response.pReason = static_cast<PCSTR>(XorStr("OK").c_str());
            response.ReasonLength = (USHORT)strlen(response.pReason);

            // https://social.msdn.microsoft.com/Forums/vstudio/en-US/6d468747-2221-4f4a-9156-f98f355a9c08/using-httph-to-set-up-an-https-server-that-is-queried-by-a-client-that-uses-cross-origin-requests?forum=vcgeneral
            HTTP_UNKNOWN_HEADER  accessControlHeader;
            const char testCustomHeader[] = "Access-Control-Allow-Origin";
            const char testCustomHeaderVal[] = "*";
            accessControlHeader.pName = testCustomHeader;
            accessControlHeader.NameLength = _countof(testCustomHeader) - 1;
            accessControlHeader.pRawValue = testCustomHeaderVal;
            accessControlHeader.RawValueLength = _countof(testCustomHeaderVal) - 1;
            response.Headers.pUnknownHeaders = &accessControlHeader;
            response.Headers.UnknownHeaderCount = 1;
            // Add an entity chunk to the response.
            // PSTR pEntityString = "Hello from C++";
            HTTP_DATA_CHUNK dataChunk;
            dataChunk.DataChunkType = HttpDataChunkFromMemory;

            result = HttpSendHttpResponse(
                requestQueueHandle,
                pRequest->RequestId,
                0,
                &response,
                NULL,
                NULL,   // &bytesSent (optional)
                NULL,
                0,
                NULL,
                NULL
            );

            delete[]buffer;
            continue;
        }

        if (!is_localhost_host(pRequest->CookedUrl.pHost) || !is_loopback_addr(pRequest->Address.pRemoteAddress)) {
            send_simple_http_response(requestQueueHandle, pRequest, 403, "Forbidden");
            delete[]buffer;
            continue;
        }

        std::wstring ws(pRequest->CookedUrl.pQueryString);
        std::string myVarS = std::string(ws.begin(), ws.end());
        std::string user = get_str_between_two_str(myVarS, "?user=", "&");
        std::string token = get_str_between_two_str(myVarS, "&token=", "");

        if (user.empty() || token.empty() || user.size() > 64 || token.size() > 128) {
            send_simple_http_response(requestQueueHandle, pRequest, 400, "Bad Request");
            delete[]buffer;
            continue;
        }

        // keyauth request
        std::string hwid = utils::get_hwid();
        auto data =
            XorStr("type=login") +
            XorStr("&username=") + user +
            XorStr("&token=") + token +
            XorStr("&hwid=") + hwid +
            XorStr("&sessionid=") + sessionid +
            XorStr("&name=") + name +
            XorStr("&ownerid=") + ownerid;
        auto resp = req(data, api::url);

        std::hash<int> hasher;
        int expectedHash = hasher(42);
        int result = VerifyPayload(signature, signatureTimestamp, resp.data());
        if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
        {
            auto json = parse_json_or_fail(resp);
            if (json[(XorStr("ownerid"))] != ownerid) {
                LI_FN(exit)(8);
            }

            std::string message = json[(XorStr("message"))];

            std::hash<int> hasher;
            size_t expectedHash = hasher(68);
            size_t resultCode = hasher(json[(XorStr("code"))]);

            if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
                if (api::response.message != XorStr("Initialized").c_str()) {
                    LI_FN(GlobalAddAtomA)(seed.c_str());

                    std::string file_path = XorStr("C:\\ProgramData\\").c_str() + seed;
                    if (!write_protected_seed_file(file_path, seed)) {
                        LI_FN(exit)(16);
                    }

                    std::string regPath = XorStr("Software\\").c_str() + seed;
                    HKEY hKey;
                    LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
                    if (result == ERROR_SUCCESS) {
                        LI_FN(RegSetValueExA)(hKey, seed.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(seed.c_str()), seed.size() + 1);
                        LI_FN(RegCloseKey)(hKey);
                    }

                    LI_FN(GlobalAddAtomA)(ownerid.c_str());
		    LoggedIn.store(true);
                }
                else {
                    LI_FN(exit)(12);
                }

                // Respond to the request.
                HTTP_RESPONSE response;
                RtlZeroMemory(&response, sizeof(response));

                bool success = true;
                if (json[(XorStr("success"))])
                {
                    load_user_data(json[(XorStr("info"))]);

                    response.StatusCode = 420;
                    response.pReason = XorStr("SHEESH").c_str();
                    response.ReasonLength = (USHORT)strlen(response.pReason);
                }
                else
                {
                    response.StatusCode = 200;
                    std::string failureReason = static_cast<std::string>(json[(XorStr("message"))]);
                    response.pReason = failureReason.c_str();
                    response.ReasonLength = (USHORT)failureReason.size();
                    success = false;
                }
                // end keyauth request

                // https://social.msdn.microsoft.com/Forums/vstudio/en-US/6d468747-2221-4f4a-9156-f98f355a9c08/using-httph-to-set-up-an-https-server-that-is-queried-by-a-client-that-uses-cross-origin-requests?forum=vcgeneral
                HTTP_UNKNOWN_HEADER  accessControlHeader;
                const char testCustomHeader[] = "Access-Control-Allow-Origin";
                const char testCustomHeaderVal[] = "*";
                accessControlHeader.pName = testCustomHeader;
                accessControlHeader.NameLength = _countof(testCustomHeader) - 1;
                accessControlHeader.pRawValue = testCustomHeaderVal;
                accessControlHeader.RawValueLength = _countof(testCustomHeaderVal) - 1;
                response.Headers.pUnknownHeaders = &accessControlHeader;
                response.Headers.UnknownHeaderCount = 1;
                // Add an entity chunk to the response.
                // PSTR pEntityString = "Hello from C++";
                HTTP_DATA_CHUNK dataChunk;
                dataChunk.DataChunkType = HttpDataChunkFromMemory;

                result = HttpSendHttpResponse(
                    requestQueueHandle,
                    pRequest->RequestId,
                    0,
                    &response,
                    NULL,
                    NULL,   // &bytesSent (optional)
                    NULL,
                    0,
                    NULL,
                    NULL
                );

                if (result == NO_ERROR) {
                    going = false;
                }

                delete[]buffer;

                if (!success)
                    LI_FN(exit)(0);
            }
            else {
                LI_FN(exit)(9);
            }
        }
        else {
            LI_FN(exit)(7);
        }
    }
}

void KeyAuth::api::button(std::string button)
{
    checkInit();

    // from https://perpetualprogrammers.wordpress.com/2016/05/22/the-http-server-api/

    // Initialize the API.
    ULONG result = 0;
    HTTPAPI_VERSION version = HTTPAPI_VERSION_2;
    result = HttpInitialize(version, HTTP_INITIALIZE_SERVER, 0);

    // Create server session.
    HTTP_SERVER_SESSION_ID serverSessionId;
    result = HttpCreateServerSession(version, &serverSessionId, 0);

    // Create URL group.
    HTTP_URL_GROUP_ID groupId;
    result = HttpCreateUrlGroup(serverSessionId, &groupId, 0);

    // Create request queue.
    HANDLE requestQueueHandle;
    result = HttpCreateRequestQueue(version, NULL, NULL, 0, &requestQueueHandle);

    // Attach request queue to URL group.
    HTTP_BINDING_INFO info;
    info.Flags.Present = 1;
    info.RequestQueueHandle = requestQueueHandle;
    result = HttpSetUrlGroupProperty(groupId, HttpServerBindingProperty, &info, sizeof(info));

    // Add URLs to URL group.
    std::wstring output;
    output = std::wstring(button.begin(), button.end());
    output = std::wstring(L"http://localhost:1337/") + output;
    PCWSTR url = output.c_str();
    result = HttpAddUrlToUrlGroup(groupId, url, 0, 0);

    // Announce that it is running.
    // wprintf(L"Listening. Please submit requests to: %s\n", url);

    // req to: http://localhost:1337/buttonvaluehere
    bool going = true;
    while (going == true)
    {
        // Wait for a request.
        HTTP_REQUEST_ID requestId = 0;
        HTTP_SET_NULL_ID(&requestId);
        int bufferSize = 4096;
        int requestSize = sizeof(HTTP_REQUEST) + bufferSize;
        BYTE* buffer = new BYTE[requestSize];
        PHTTP_REQUEST pRequest = (PHTTP_REQUEST)buffer;
        RtlZeroMemory(buffer, requestSize);
        ULONG bytesReturned;
        result = HttpReceiveHttpRequest(
            requestQueueHandle,
            requestId,
            HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY,
            pRequest,
            requestSize,
            &bytesReturned,
            NULL
        );

        going = false;

        // Display some information about the request.
        // wprintf(L"Full URL: %ws\n", pRequest->CookedUrl.pFullUrl);
        // wprintf(L"    Path: %ws\n", pRequest->CookedUrl.pAbsPath);
        // wprintf(L"    Query: %ws\n", pRequest->CookedUrl.pQueryString);

        // std::cout << get_str_between_two_str(CW2A(pRequest->CookedUrl.pQueryString), "?", "&") << std::endl;

        // Break from the loop if it's the poison pill (a DELETE request).
        // if (pRequest->Verb == HttpVerbDELETE)
        // {
        //     wprintf(L"Asked to stop.\n");
        //     break;
        // }

        // Respond to the request.
        HTTP_RESPONSE response;
        RtlZeroMemory(&response, sizeof(response));
        response.StatusCode = 420;
        response.pReason = XorStr("SHEESH").c_str();
        response.ReasonLength = (USHORT)strlen(response.pReason);

        // https://social.msdn.microsoft.com/Forums/vstudio/en-US/6d468747-2221-4f4a-9156-f98f355a9c08/using-httph-to-set-up-an-https-server-that-is-queried-by-a-client-that-uses-cross-origin-requests?forum=vcgeneral
        HTTP_UNKNOWN_HEADER  accessControlHeader;
        const char testCustomHeader[] = "Access-Control-Allow-Origin";
        const char testCustomHeaderVal[] = "*";
        accessControlHeader.pName = testCustomHeader;
        accessControlHeader.NameLength = _countof(testCustomHeader) - 1;
        accessControlHeader.pRawValue = testCustomHeaderVal;
        accessControlHeader.RawValueLength = _countof(testCustomHeaderVal) - 1;
        response.Headers.pUnknownHeaders = &accessControlHeader;
        response.Headers.UnknownHeaderCount = 1;
        // Add an entity chunk to the response.
        // PSTR pEntityString = "Hello from C++";
        HTTP_DATA_CHUNK dataChunk;
        dataChunk.DataChunkType = HttpDataChunkFromMemory;

        result = HttpSendHttpResponse(
            requestQueueHandle,
            pRequest->RequestId,
            0,
            &response,
            NULL,
            NULL,   // &bytesSent (optional)
            NULL,
            0,
            NULL,
            NULL
        );

        delete[]buffer;
    }
}

void KeyAuth::api::regstr(std::string username, std::string password, std::string key, std::string email) {
    checkInit();

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=register") +
        XorStr("&username=") + username +
        XorStr("&pass=") + password +
        XorStr("&key=") + key +
        XorStr("&email=") + email +
        XorStr("&hwid=") + hwid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    secure_clear_string(data);
    secure_clear_string(password);
    secure_clear_string(key);
    secure_clear_string(email);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = parse_json_or_fail(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {

            load_response_data(json);
            if (json[(XorStr("success"))])
                load_user_data(json[(XorStr("info"))]);

            if (api::response.message != XorStr("Initialized").c_str()) {
                LI_FN(GlobalAddAtomA)(seed.c_str());

                std::string file_path = XorStr("C:\\ProgramData\\").c_str() + seed;
                if (!write_protected_seed_file(file_path, seed)) {
                    LI_FN(exit)(16);
                }

                std::string regPath = XorStr("Software\\").c_str() + seed;
                HKEY hKey;
                LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
                if (result == ERROR_SUCCESS) {
                    LI_FN(RegSetValueExA)(hKey, seed.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(seed.c_str()), seed.size() + 1);
                    LI_FN(RegCloseKey)(hKey);
                }

                LI_FN(GlobalAddAtomA)(ownerid.c_str());
		LoggedIn.store(true);
            }
            else {
                LI_FN(exit)(12);
            }
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else
    {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::upgrade(std::string username, std::string key) {
    checkInit();

    auto data =
        XorStr("type=upgrade") +
        XorStr("&username=") + username +
        XorStr("&key=") + key +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    secure_clear_string(data);
    secure_clear_string(key);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = parse_json_or_fail(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {

            json[(XorStr("success"))] = false;
            load_response_data(json);
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

std::string generate_random_number() {
    if (sodium_init() < 0) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist_length(5, 10);
        std::uniform_int_distribution<> dist_digit(0, 9);
        const int fallbackLength = dist_length(gen);
        std::string fallback;
        fallback.reserve(fallbackLength);
        for (int i = 0; i < fallbackLength; ++i) {
            fallback.push_back(static_cast<char>('0' + dist_digit(gen)));
        }
        return fallback;
    }

    const int length = static_cast<int>(randombytes_uniform(6)) + 5; // 5..10 digits
    std::string random_number;
    for (int i = 0; i < length; ++i) {
        const int digit = static_cast<int>(randombytes_uniform(10));
        random_number.push_back(static_cast<char>('0' + digit));
    }
    return random_number;
}

void KeyAuth::api::license(std::string key, std::string code) {
    checkInit();

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=license") +
        XorStr("&key=") + key +
        XorStr("&code=") + code +
        XorStr("&hwid=") + hwid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    secure_clear_string(data);
    secure_clear_string(key);
    secure_clear_string(code);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = parse_json_or_fail(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
            if (json[(XorStr("success"))])
                load_user_data(json[(XorStr("info"))]);

            if (api::response.message != XorStr("Initialized").c_str()) {
                LI_FN(GlobalAddAtomA)(seed.c_str());

                std::string file_path = XorStr("C:\\ProgramData\\").c_str() + seed;
                if (!write_protected_seed_file(file_path, seed)) {
                    LI_FN(exit)(16);
                }

                std::string regPath = XorStr("Software\\").c_str() + seed;
                HKEY hKey;
                LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, regPath.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
                if (result == ERROR_SUCCESS) {
                    LI_FN(RegSetValueExA)(hKey, seed.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(seed.c_str()), seed.size() + 1);
                    LI_FN(RegCloseKey)(hKey);
                }

                LI_FN(GlobalAddAtomA)(ownerid.c_str());
		LoggedIn.store(true);
            }
            else {
                LI_FN(exit)(12);
            }
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::setvar(std::string var, std::string vardata) {
    checkInit();

    auto data =
        XorStr("type=setvar") +
        XorStr("&var=") + var +
        XorStr("&data=") + vardata +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    auto json = parse_json_or_fail(response);
    load_response_data(json);
}

std::string KeyAuth::api::getvar(std::string var) {
    checkInit();

    auto data =
        XorStr("type=getvar") +
        XorStr("&var=") + var +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = parse_json_or_fail(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
            return !json[(XorStr("response"))].is_null() ? json[(XorStr("response"))] : XorStr("");
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::ban(std::string reason) {
    checkInit();

    auto data =
        XorStr("type=ban") +
        XorStr("&reason=") + reason +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = parse_json_or_fail(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else
    {
        LI_FN(exit)(7);
    }
}

bool KeyAuth::api::checkblack() {
    checkInit();

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=checkblacklist") +
        XorStr("&hwid=") + hwid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = parse_json_or_fail(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            return json[("success")];
        }
        LI_FN(exit)(9);
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::check(bool check_paid) {
    checkInit();

    auto data =
        XorStr("type=check") +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    std::string endpoint = url;
    if (check_paid) {
        endpoint += "?check_paid=1";
    }

    auto response = req(data, endpoint);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = parse_json_or_fail(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

std::string KeyAuth::api::var(std::string varid) {
    checkInit();

    auto data =
        XorStr("type=var") +
        XorStr("&varid=") + varid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = parse_json_or_fail(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
            return json[(XorStr("message"))];
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::log(std::string message) {
    checkInit();

    char acUserName[100];
    DWORD nUserName = sizeof(acUserName);
    GetUserNameA(acUserName, &nUserName);
    std::string UsernamePC = acUserName;

    auto data =
        XorStr("type=log") +
        XorStr("&pcuser=") + UsernamePC +
        XorStr("&message=") + message +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    req(data, url);
}

std::vector<unsigned char> KeyAuth::api::download(std::string fileid) {
    checkInit();

    auto to_uc_vector = [](std::string value) {
        return std::vector<unsigned char>(value.data(), value.data() + value.length() );
    };


    auto data =
        XorStr("type=file") +
        XorStr("&fileid=") + fileid +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=").c_str() + ownerid;

    auto response = req(data, url);
    auto json = parse_json_or_fail(response);
    std::string message = json[(XorStr("message"))];

    load_response_data(json);
    if (json[ XorStr( "success" ) ])
    {
        auto file = hexDecode(json[ XorStr( "contents" )]);
        return to_uc_vector(file);
    }
    return {};
}


std::string KeyAuth::api::webhook(std::string id, std::string params, std::string body, std::string contenttype)
{
    checkInit();

    CURL *curl = curl_easy_init();
    std::string encodedParams = escape_for_post(curl, params);
    std::string encodedBody = escape_for_post(curl, body);
    auto data =
        XorStr("type=webhook") +
        XorStr("&webid=") + id +
        XorStr("&params=") + encodedParams +
        XorStr("&body=") + encodedBody +
        XorStr("&conttype=") + contenttype +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    if (curl) {
        curl_easy_cleanup(curl);
    }
    auto response = req(data, url);
    secure_clear_string(data);
    secure_clear_string(params);
    secure_clear_string(body);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = parse_json_or_fail(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {

            load_response_data(json);
            return !json[(XorStr("response"))].is_null() ? json[(XorStr("response"))] : XorStr("");
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

std::string KeyAuth::api::fetchonline() 
{
    checkInit();

    auto data =
        XorStr("type=fetchOnline") +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = parse_json_or_fail(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            std::string onlineusers;

            int y = atoi(api::app_data.numOnlineUsers.c_str());
            for (int i = 0; i < y; i++)
            {
                onlineusers.append(json[XorStr("users")][i][XorStr("credential")]); onlineusers.append(XorStr("\n"));
            }

            return onlineusers;
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::fetchstats()
{
    checkInit();

    auto data =
        XorStr("type=fetchStats") +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;

    auto response = req(data, url);
    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response.data());
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {

        auto json = parse_json_or_fail(response);
        if (json[(XorStr("ownerid"))] != ownerid) {
            LI_FN(exit)(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {

            load_response_data(json);

            if (json[(XorStr("success"))])
                load_app_data(json[(XorStr("appinfo"))]);
        }
        else {
            LI_FN(exit)(9);
        }
    }
    else {
        LI_FN(exit)(7);
    }
}

void KeyAuth::api::forgot(std::string username, std::string email)
{
    checkInit();

    auto data =
        XorStr("type=forgot") +
        XorStr("&username=") + username +
        XorStr("&email=") + email +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    secure_clear_string(data);
    secure_clear_string(email);
    auto json = parse_json_or_fail(response);
    load_response_data(json);
}

void KeyAuth::api::logout() {
    checkInit();

    auto data =
        XorStr("type=logout") +
        XorStr("&sessionid=") + sessionid +
        XorStr("&name=") + name +
        XorStr("&ownerid=") + ownerid;
    auto response = req(data, url);
    auto json = parse_json_or_fail(response);
    if (json[(XorStr("success"))]) {

        //clear all old user data from program
        user_data.createdate.clear();
        user_data.ip.clear();
        user_data.hwid.clear();
        user_data.lastlogin.clear();
        user_data.username.clear();
        user_data.subscriptions.clear();

        //clear sessionid
        sessionid.clear();

        //clear enckey
        enckey.clear();

    }

    load_response_data(json);
}

// stricter signed-payload validation and sensitive buffer zeroization -nigel
int VerifyPayload(std::string signature, std::string timestamp, std::string body)
{
    if (signature.size() != 128 || !is_hex_ascii(signature)) {
        MessageBoxA(0, "Signature verification failed (invalid signature header)", "KeyAuth", MB_ICONERROR);
        exit(5);
    }
    if (!is_decimal_ascii(timestamp) || timestamp.size() > 20) {
        MessageBoxA(0, "Signature verification failed (invalid timestamp header)", "KeyAuth", MB_ICONERROR);
        exit(2);
    }

    long long unix_timestamp = 0;
    try {
        unix_timestamp = std::stoll(timestamp);
    }
    catch (...) {
        MessageBoxA(0, "Signature verification failed (invalid timestamp)", "KeyAuth", MB_ICONERROR);
        exit(2);
    }

    auto current_time = std::chrono::system_clock::now();
    long long current_unix_time = std::chrono::duration_cast<std::chrono::seconds>(
        current_time.time_since_epoch()).count();

    const long long delta = current_unix_time - unix_timestamp;
    if (delta > kMaxAllowedClockSkewSeconds || delta < -kMaxAllowedClockSkewSeconds) {
        std::cerr << "[ERROR] Timestamp too old (diff = "
            << delta << "s)\n";
        MessageBoxA(0, "Signature verification failed (invalid timestamp skew)", "KeyAuth", MB_ICONERROR);
        exit(3);
    }

    if (sodium_init() < 0) {
        std::cerr << "[ERROR] Failed to initialize libsodium\n";
        MessageBoxA(0, "Signature verification failed (libsodium init)", "KeyAuth", MB_ICONERROR);
        exit(4);
    }

    std::string message = timestamp + body;

    unsigned char sig[64];
    unsigned char pk[32];

    if (sodium_hex2bin(sig, sizeof(sig), signature.c_str(), signature.length(), NULL, NULL, NULL) != 0) {
        std::cerr << "[ERROR] Failed to parse signature hex.\n";
        MessageBoxA(0, "Signature verification failed (invalid signature format)", "KeyAuth", MB_ICONERROR);
        exit(5);
    }

    if (sodium_hex2bin(pk, sizeof(pk), API_PUBLIC_KEY.c_str(), API_PUBLIC_KEY.length(), NULL, NULL, NULL) != 0) {
        std::cerr << "[ERROR] Failed to parse public key hex.\n";
        MessageBoxA(0, "Signature verification failed (invalid public key)", "KeyAuth", MB_ICONERROR);
        exit(6);
    }

    /*std::cout << "[DEBUG] Timestamp: " << timestamp << std::endl;
    std::cout << "[DEBUG] Signature: " << signature << std::endl;
    std::cout << "[DEBUG] Body: " << body << std::endl;
    std::cout << "[DEBUG] Message (timestamp + body): " << message << std::endl;
    std::cout << "[DEBUG] Public Key: " << API_PUBLIC_KEY << std::endl;*/

    if (crypto_sign_ed25519_verify_detached(sig,
        reinterpret_cast<const unsigned char*>(message.c_str()),
        message.length(),
        pk) != 0)
    {
        sodium_memzero(sig, sizeof(sig));
        sodium_memzero(pk, sizeof(pk));
        std::cerr << "[ERROR] Signature verification failed.\n";
        MessageBoxA(0, "Signature verification failed (invalid signature)", "KeyAuth", MB_ICONERROR);
        exit(7);
    }
    sodium_memzero(sig, sizeof(sig));
    sodium_memzero(pk, sizeof(pk));

    //std::cout << "[DEBUG] Payload verified successfully.\n";

    int value = 42 ^ 0xA5A5;
    return value & 0xFFFF;
}


// credits https://stackoverflow.com/a/3790661
static std::string hexDecode(const std::string& hex)
{
    int len = hex.length();
    std::string newString;
    for (int i = 0; i < len; i += 2)
    {
        std::string byte = hex.substr(i, 2);
        char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
        newString.push_back(chr);
    }
    return newString;
}
// credits https://stackoverflow.com/a/43002794
std::string get_str_between_two_str(const std::string& s,
    const std::string& start_delim,
    const std::string& stop_delim)
{
    const std::size_t first_delim_pos = s.find(start_delim);
    if (first_delim_pos == std::string::npos) {
        return "";
    }

    const std::size_t end_pos_of_first_delim = first_delim_pos + start_delim.length();
    if (stop_delim.empty()) {
        return s.substr(end_pos_of_first_delim);
    }

    const std::size_t last_delim_pos = s.find(stop_delim, end_pos_of_first_delim);
    if (last_delim_pos == std::string::npos || last_delim_pos < end_pos_of_first_delim) {
        return "";
    }

    return s.substr(end_pos_of_first_delim, last_delim_pos - end_pos_of_first_delim);
}

void KeyAuth::api::setDebug(bool value) {
    KeyAuth::api::debug = value;
}

// hardened request policy (HTTPS-only, limits, signed response enforcement) -nigel
std::string KeyAuth::api::req(std::string data, const std::string& url) {
    signature.clear();
    signatureTimestamp.clear();

    if (data.size() > kMaxRequestBytes) {
        error(XorStr("Request too large."));
    }

    // stricter URL sanitization for transport endpoint input -nigel
    if (!is_transport_url_safe(url)) {
        error(XorStr("Unsafe API URL format. Use a valid HTTPS URL."));
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        error(XorStr("CURL Initialization Failed!"));
    }

    ResponseBuffer responseBuffer;
    std::string headers;

    // Set CURL options
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
#if defined(CURLSSLOPT_REVOKE_BEST_EFFORT) || defined(CURLSSLOPT_NATIVE_CA)
    // enable revocation/native CA behavior when supported by this curl build -nigel
    long sslOptions = 0;
#ifdef CURLSSLOPT_REVOKE_BEST_EFFORT
    sslOptions |= CURLSSLOPT_REVOKE_BEST_EFFORT;
#endif
#ifdef CURLSSLOPT_NATIVE_CA
    sslOptions |= CURLSSLOPT_NATIVE_CA;
#endif
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, sslOptions);
#endif
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, kRequestTimeoutMs);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, kRequestTimeoutMs);
    curl_easy_setopt(curl, CURLOPT_DISALLOW_USERNAME_IN_URL, 1L);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 0L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_NETRC, CURL_NETRC_IGNORED);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_NONE);
    curl_easy_setopt(curl, CURLOPT_PROXYAUTH, CURLAUTH_NONE);
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR, "");
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
    curl_easy_setopt(curl, CURLOPT_NOPROXY, XorStr("keyauth.win").c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(data.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headers);

    // Perform the request
    CURLcode code = curl_easy_perform(curl);
    if (code != CURLE_OK) {
        std::string errorMsg = "CURL Error: " + std::string(curl_easy_strerror(code));
        curl_easy_cleanup(curl);  
        error(errorMsg);
    }
    // reject non-success HTTP status codes before processing response body -nigel
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    if (httpCode < 200 || httpCode >= 300) {
        curl_easy_cleanup(curl);
        error(XorStr("Unexpected HTTP status from API."));
    }
    if (responseBuffer.overflow) {
        curl_easy_cleanup(curl);
        error(XorStr("Response too large."));
    }

    if (signature.empty() || signatureTimestamp.empty()) {
        curl_easy_cleanup(curl);
        error(XorStr("Missing response signature headers."));
    }

    VerifyPayload(signature, signatureTimestamp, responseBuffer.body);

    debugInfo(data, url, responseBuffer.body, "Sig: " + signature + "\nTimestamp:" + signatureTimestamp);
    secure_clear_string(data);
    curl_easy_cleanup(curl); 
    return responseBuffer.body;
}

void error(std::string message) {
    MessageBoxA(nullptr, message.c_str(), "KeyAuth", MB_ICONERROR);
    OutputDebugStringA(message.c_str());
    LI_FN(__fastfail)(0);
}
// section integrity verification hardened for reliability and handle safety -nigel
auto check_section_integrity(const char* section_name, bool fix = false) -> bool
{
    if (!section_name || !*section_name) {
        return true;
    }

    HMODULE hmodule = GetModuleHandle(nullptr);
    if (!hmodule) {
        return true;
    }

    const auto loadedBase = reinterpret_cast<std::uintptr_t>(hmodule);
    const auto loadedDos = reinterpret_cast<IMAGE_DOS_HEADER*>(loadedBase);
    if (!loadedDos || loadedDos->e_magic != IMAGE_DOS_SIGNATURE) {
        return true;
    }

    const auto loadedNt = reinterpret_cast<IMAGE_NT_HEADERS*>(loadedBase + loadedDos->e_lfanew);
    if (!loadedNt || loadedNt->Signature != IMAGE_NT_SIGNATURE) {
        return true;
    }

    wchar_t filename[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameW(GetCurrentProcess(), 0, filename, &size)) {
        return true;
    }

    HANDLE fileHandle = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!fileHandle || fileHandle == INVALID_HANDLE_VALUE) {
        return true;
    }

    HANDLE fileMapping = CreateFileMappingW(fileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!fileMapping) {
        CloseHandle(fileHandle);
        return true;
    }

    auto* mappedView = static_cast<std::uint8_t*>(MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0));
    if (!mappedView) {
        CloseHandle(fileMapping);
        CloseHandle(fileHandle);
        return true;
    }

    const auto mappedBase = reinterpret_cast<std::uintptr_t>(mappedView);
    const auto mappedDos = reinterpret_cast<IMAGE_DOS_HEADER*>(mappedBase);
    if (!mappedDos || mappedDos->e_magic != IMAGE_DOS_SIGNATURE) {
        UnmapViewOfFile(mappedView);
        CloseHandle(fileMapping);
        CloseHandle(fileHandle);
        return true;
    }

    const auto mappedNt = reinterpret_cast<IMAGE_NT_HEADERS*>(mappedBase + mappedDos->e_lfanew);
    if (!mappedNt || mappedNt->Signature != IMAGE_NT_SIGNATURE ||
        mappedNt->FileHeader.TimeDateStamp != loadedNt->FileHeader.TimeDateStamp ||
        mappedNt->FileHeader.NumberOfSections != loadedNt->FileHeader.NumberOfSections) {
        UnmapViewOfFile(mappedView);
        CloseHandle(fileMapping);
        CloseHandle(fileHandle);
        return true;
    }

    auto* loadedSection = IMAGE_FIRST_SECTION(loadedNt);
    auto* mappedSection = IMAGE_FIRST_SECTION(mappedNt);
    bool patched = false;
    char targetSectionName[8] = { 0 };
    std::memcpy(targetSectionName, section_name, (std::min<std::size_t>)(8, std::strlen(section_name)));

    for (WORD i = 0; i < mappedNt->FileHeader.NumberOfSections; ++i, ++loadedSection, ++mappedSection) {
        const bool sectionNameMatch = std::memcmp(loadedSection->Name, targetSectionName, sizeof(targetSectionName)) == 0;
        if (!sectionNameMatch || !(loadedSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            continue;
        }

        const std::size_t rawSize = static_cast<std::size_t>(mappedSection->SizeOfRawData);
        const std::size_t virtSize = static_cast<std::size_t>(loadedSection->Misc.VirtualSize);
        const std::size_t compareSize = (virtSize == 0) ? rawSize : (std::min)(rawSize, virtSize);
        if (compareSize == 0) {
            break;
        }

        auto* mappedBytes = reinterpret_cast<std::uint8_t*>(mappedBase + mappedSection->PointerToRawData);
        auto* loadedBytes = reinterpret_cast<std::uint8_t*>(loadedBase + loadedSection->VirtualAddress);

        for (std::size_t offset = 0; offset < compareSize; ++offset) {
            if (loadedBytes[offset] == mappedBytes[offset]) {
                continue;
            }

            if (fix) {
                DWORD oldProtect = 0;
                if (VirtualProtect(loadedBytes + offset, sizeof(std::uint8_t), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    loadedBytes[offset] = mappedBytes[offset];
                    DWORD ignoreProtect = 0;
                    VirtualProtect(loadedBytes + offset, sizeof(std::uint8_t), oldProtect, &ignoreProtect);
                }
            }
            patched = true;
        }
        break;
    }

    UnmapViewOfFile(mappedView);
    CloseHandle(fileMapping);
    CloseHandle(fileHandle);
    return patched;
}

void runChecks() {
   // Wait before starting checks
   int waitTime = 45000; 
   while (waitTime > 0) {

        if (LoggedIn.load()) {
	    // If the user is logged in, proceed with the checks immediately
            break;
         }
         std::this_thread::sleep_for(std::chrono::seconds(1));
         waitTime -= 1000;
    }

    // Create separate threads for each check
    std::thread(checkAtoms).detach(); 
    std::thread(checkFiles).detach(); 
    std::thread(checkRegistry).detach();
}

void checkAtoms() {

    while (true) {
        if (LI_FN(GlobalFindAtomA)(seed.c_str()) == 0) {
            LI_FN(exit)(13);
            LI_FN(__fastfail)(0);
        }
        Sleep(1000); // thread interval
    }
}

void checkFiles() {

    while (true) {
        std::string file_path = XorStr("C:\\ProgramData\\").c_str() + seed;
        DWORD file_attr = LI_FN(GetFileAttributesA)(file_path.c_str());
        if (file_attr == INVALID_FILE_ATTRIBUTES || (file_attr & FILE_ATTRIBUTE_DIRECTORY)) {
            LI_FN(exit)(14);
            LI_FN(__fastfail)(0);
        }
        Sleep(2000); // thread interval, files are more intensive than Atom tables which use memory
    }
}

void checkRegistry() {
	
    while (true) {
        std::string regPath = XorStr("Software\\").c_str() + seed;
        HKEY hKey;
        LONG result = LI_FN(RegOpenKeyExA)(HKEY_CURRENT_USER, regPath.c_str(), 0, KEY_READ, &hKey);
        if (result != ERROR_SUCCESS) {
            LI_FN(exit)(15);
            LI_FN(__fastfail)(0);
        }
        LI_FN(RegCloseKey)(hKey);
	Sleep(1500); // thread interval
    }
}

std::string checksum()
{
    char rawPathName[MAX_PATH];
    GetModuleFileNameA(NULL, rawPathName, MAX_PATH);

    return md5_file_hex(std::string(rawPathName));
}

std::string getPath() {
    const char* programDataPath = std::getenv("ALLUSERSPROFILE");

    if (programDataPath != nullptr) {
        return std::string(programDataPath);
    }
    else {

        return std::filesystem::current_path().string();
    }
}

void RedactField(nlohmann::json& jsonObject, const std::string& fieldName)
{

    if (jsonObject.contains(fieldName)) {
        jsonObject[fieldName] = "REDACTED";
    }
}

void KeyAuth::api::debugInfo(std::string data, std::string url, std::string response, std::string headers) {
    // output debug logs to C:\ProgramData\KeyAuth\Debug

    if (!KeyAuth::api::debug) {
        return;
    }

    std::string redacted_response = "n/a";
    // for logging the headers, since response is not avaliable there
    if (response != "n/a") {
        try {
            // turn response into json
            nlohmann::json responses = nlohmann::json::parse(response);
            RedactField(responses, "sessionid");
            RedactField(responses, "ownerid");
            RedactField(responses, "app");
            RedactField(responses, "name");
            RedactField(responses, "contents");
            RedactField(responses, "key");
            RedactField(responses, "username");
            RedactField(responses, "password");
            RedactField(responses, "version");
            RedactField(responses, "fileid");
            RedactField(responses, "webhooks");
            redacted_response = responses.dump();
        }
        catch (...) {
            redacted_response = "non-json response";
        }
    }

    std::string redacted_data = "n/a";
    // for logging the headers, since request JSON is not avaliable there
    if (data != "n/a") {
        //turn data into json
        std::replace(data.begin(), data.end(), '&', ' ');

        nlohmann::json datas;

        std::istringstream iss(data);
        std::vector<std::string> results((std::istream_iterator<std::string>(iss)),
            std::istream_iterator<std::string>());

        for (auto const& value : results) {
            datas[value.substr(0, value.find('='))] = value.substr(value.find('=') + 1);
        }

        RedactField(datas, "sessionid");
        RedactField(datas, "ownerid");
        RedactField(datas, "app");
        RedactField(datas, "name");
        RedactField(datas, "key");
        RedactField(datas, "username");
        RedactField(datas, "password");
        RedactField(datas, "contents");
        RedactField(datas, "version");
        RedactField(datas, "fileid");
        RedactField(datas, "webhooks");

        redacted_data = datas.dump();
    }

    //gets the path
    std::string path = getPath();

    //fetch filename

    TCHAR filename[MAX_PATH];
    GetModuleFileName(NULL, filename, MAX_PATH);

    TCHAR* filename_only = PathFindFileName(filename);

    std::wstring filenameOnlyString(filename_only);

    std::string filenameOnly(filenameOnlyString.begin(), filenameOnlyString.end());

    ///////////////////////

    //creates variables for the paths needed :smile:
    std::string KeyAuthPath = path + "\\KeyAuth";
    std::string logPath = KeyAuthPath + "\\Debug\\" + filenameOnly.substr(0, filenameOnly.size() - 4);

    //basically loops until we have all the paths
    if (!std::filesystem::exists(KeyAuthPath) || !std::filesystem::exists(KeyAuthPath + "\\Debug") || !std::filesystem::exists(logPath)) {

        if (!std::filesystem::exists(KeyAuthPath)) { std::filesystem::create_directory(KeyAuthPath); }

        if (!std::filesystem::exists(KeyAuthPath + "\\Debug")) { std::filesystem::create_directory(KeyAuthPath + "\\Debug"); }

        if (!std::filesystem::exists(logPath)) { std::filesystem::create_directory(logPath); }

    }

    if (response.length() >= 500) { return; }

    //fetch todays time
    std::time_t t = std::time(nullptr);
    char time[80];

    std::tm* localTime = std::localtime(&t);

    std::strftime(time, sizeof(time), "%m-%d-%Y", localTime);

    std::ofstream logfile(logPath + "\\" + time + ".txt", std::ios::app);

    //get time
    int hours = localTime->tm_hour;
    int minutes = localTime->tm_min;

    std::string period;
    if (hours < 12) {
        period = "AM";
    }
    else {
        period = "PM";
        hours -= 12;
    }

    std::string formattedMinutes = (minutes < 10) ? "0" + std::to_string(minutes) : std::to_string(minutes);

    std::string currentTimeString = std::to_string(hours) + ":" + formattedMinutes + " " + period;

    std::string contents = "\n\n@ " + currentTimeString + "\nURL: " + url + "\nData sent : " + redacted_data + "\nResponse : " + redacted_response + "\n" + headers;

    logfile << contents;

    logfile.close();
}

void checkInit() {
    if (!initialized.load()) {
        error(XorStr("You need to run the KeyAuthApp.init(); function before any other KeyAuth functions"));
    }
}
// code submitted in pull request from https://github.com/BINM7MD
BOOL bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
    {
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    }
    return (*szMask) == NULL;
}
DWORD64 FindPattern(BYTE* bMask, const char* szMask)
{
    MODULEINFO mi{ };
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(NULL), &mi, sizeof(mi))) {
        return 0;
    }

    DWORD64 dwBaseAddress = DWORD64(mi.lpBaseOfDll);
    const auto dwModuleSize = static_cast<std::size_t>(mi.SizeOfImage);
    const auto maskLen = szMask ? std::strlen(szMask) : 0;
    if (!bMask || !szMask || maskLen == 0 || maskLen > dwModuleSize) {
        return 0;
    }

    for (std::size_t i = 0; i <= (dwModuleSize - maskLen); i++)
    {
        if (bDataCompare(PBYTE(dwBaseAddress + i), bMask, szMask))
            return DWORD64(dwBaseAddress + i);
    }
    return 0;
}

DWORD64 Function_Address;

// detect common usermode hook/instrumentation modules -nigel
static bool has_suspicious_module_loaded()
{
    HMODULE modules[1024]{};
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &needed)) {
        return false;
    }

    const unsigned int moduleCount = needed / sizeof(HMODULE);
    const std::wstring blocked[] = {
        L"frida-agent.dll", L"frida-gadget.dll", L"easyhook64.dll", L"easyhook32.dll",
        L"detoured.dll", L"scyllahide.dll", L"dbghelp.dll"
    };

    for (unsigned int i = 0; i < moduleCount; ++i) {
        wchar_t name[MAX_PATH]{};
        if (GetModuleBaseNameW(GetCurrentProcess(), modules[i], name, MAX_PATH) == 0) {
            continue;
        }
        std::wstring lowered(name);
        std::transform(lowered.begin(), lowered.end(), lowered.begin(),
            [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
        for (const auto& item : blocked) {
            if (lowered == item) {
                return true;
            }
        }
    }

    return false;
}

static bool is_writable_page_protection(DWORD protect)
{
    const DWORD writableMask = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (protect & writableMask) != 0;
}

static bool is_executable_page_protection(DWORD protect)
{
    const DWORD execMask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (protect & execMask) != 0;
}

// verify executable code section is not writable in memory -nigel
static bool section_has_writable_pages(const char* section_name)
{
    if (!section_name || !*section_name) {
        return true;
    }

    HMODULE hmodule = GetModuleHandle(nullptr);
    if (!hmodule) {
        return true;
    }

    const auto base = reinterpret_cast<std::uintptr_t>(hmodule);
    const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return true;
    }
    const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
        return true;
    }

    char targetSectionName[8] = { 0 };
    std::memcpy(targetSectionName, section_name, (std::min<std::size_t>)(8, std::strlen(section_name)));
    auto* section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::memcmp(section->Name, targetSectionName, sizeof(targetSectionName)) != 0) {
            continue;
        }

        const std::uintptr_t start = base + section->VirtualAddress;
        const std::size_t sectionSize = section->Misc.VirtualSize ? section->Misc.VirtualSize : section->SizeOfRawData;
        const std::uintptr_t end = start + sectionSize;
        std::uintptr_t cursor = start;
        bool sawExecutable = false;
        while (cursor < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi))) {
                return true;
            }
            if (mbi.State == MEM_COMMIT) {
                if (is_executable_page_protection(mbi.Protect)) {
                    sawExecutable = true;
                }
                if (is_writable_page_protection(mbi.Protect)) {
                    // reduce false positives: only treat writable executable pages as tamper -nigel
                    if (is_executable_page_protection(mbi.Protect)) {
                        return true;
                    }
                }
            }
            const std::uintptr_t next = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (next <= cursor) {
                return true;
            }
            cursor = next;
        }
        // if we never saw executable pages in .text, something is off -nigel
        return !sawExecutable;
    }

    return true;
}

static bool is_localhost_host(const wchar_t* host);
static bool is_loopback_addr(const SOCKADDR* addr);
static void send_simple_http_response(HANDLE requestQueueHandle, PHTTP_REQUEST pRequest, USHORT status, const char* reason);

static bool is_localhost_host(const wchar_t* host)
{
    if (!host) {
        return false;
    }
    if (_wcsicmp(host, L"localhost") == 0) {
        return true;
    }
    if (_wcsicmp(host, L"127.0.0.1") == 0) {
        return true;
    }
    if (_wcsicmp(host, L"::1") == 0) {
        return true;
    }
    if (_wcsicmp(host, L"[::1]") == 0) {
        return true;
    }
    return false;
}

static bool is_loopback_addr(const SOCKADDR* addr)
{
    if (!addr) {
        return false;
    }
    if (addr->sa_family == AF_INET) {
        const SOCKADDR_IN* in = reinterpret_cast<const SOCKADDR_IN*>(addr);
        return in->sin_addr.S_un.S_addr == htonl(INADDR_LOOPBACK);
    }
    return false;
}

static void send_simple_http_response(HANDLE requestQueueHandle, PHTTP_REQUEST pRequest, USHORT status, const char* reason)
{
    HTTP_RESPONSE response{};
    response.StatusCode = status;
    response.pReason = reason;
    response.ReasonLength = static_cast<USHORT>(strlen(reason));
    HttpSendHttpResponse(
        requestQueueHandle,
        pRequest->RequestId,
        0,
        &response,
        nullptr,
        nullptr,
        nullptr,
        0,
        nullptr,
        nullptr
    );
}

void modify()
{
    // anti-tamper loop hardened for reliability and reduced false positives -nigel
    constexpr DWORD kLoopSleepMs = 250;
    constexpr int kSectionFailThreshold = 2;
    constexpr int kLockMemFailThreshold = 3;
    constexpr int kPatternFailThreshold = 3;
    constexpr int kDebuggerFailThreshold = 2;
    constexpr int kModuleFailThreshold = 2;
    constexpr int kWritableTextFailThreshold = 2;
    int sectionFailures = 0;
    int lockMemFailures = 0;
    int patternFailures = 0;
    int debuggerFailures = 0;
    int moduleFailures = 0;
    int writableTextFailures = 0;

    check_section_integrity(XorStr(".text").c_str(), true);

    while (true)
    {
        // runtime anti-debug/anti-hook check -nigel
        protection::init();
        const bool injectionCompat = allow_injection_compat();
        if (!injectionCompat && !protection::heartbeat()) {
            error(XorStr("Environment integrity checks failed, don't tamper with the program."));
        }

        // local debugger presence check with threshold to reduce transient false positives -nigel
        BOOL remoteDebugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
        if (IsDebuggerPresent() || remoteDebugger) {
            if (++debuggerFailures >= kDebuggerFailThreshold) {
                error(XorStr("Debugger detected, don't tamper with the program."));
            }
        }
        else {
            debuggerFailures = 0;
        }

        if (check_section_integrity(XorStr(".text").c_str(), false)) {
            if (++sectionFailures >= kSectionFailThreshold) {
                error(XorStr("check_section_integrity() failed, don't tamper with the program."));
            }
        }
        else {
            sectionFailures = 0;
        }

        if (!LockMemAccess()) {
            if (++lockMemFailures >= kLockMemFailThreshold) {
                error(XorStr("LockMemAccess() failed, don't tamper with the program."));
            }
        }
        else {
            lockMemFailures = 0;
        }

        // detect common hook/instrumentation modules in-process -nigel
        if (has_suspicious_module_loaded()) {
            if (++moduleFailures >= kModuleFailThreshold) {
                error(XorStr("Suspicious module detected, don't tamper with the program."));
            }
        }
        else {
            moduleFailures = 0;
        }

        // executable section should never remain writable in normal flow -nigel
        if (section_has_writable_pages(XorStr(".text").c_str())) {
            if (++writableTextFailures >= kWritableTextFailThreshold) {
                error(XorStr("Writable code section detected, don't tamper with the program."));
            }
        }
        else {
            writableTextFailures = 0;
        }

        if (Function_Address == 0) {
            const DWORD64 located = FindPattern(PBYTE("\x48\x89\x74\x24\x00\x57\x48\x81\xec\x00\x00\x00\x00\x49\x8b\xf0"), XorStr("xxxx?xxxx????xxx").c_str());
            if (located <= 5) {
                if (++patternFailures >= kPatternFailThreshold) {
                    error(XorStr("Pattern checksum locate failed."));
                }
            }
            else {
                Function_Address = located - 0x5;
                patternFailures = 0;
            }
        }

        if (Function_Address != 0) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(Function_Address), &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) {
                if (++patternFailures >= kPatternFailThreshold) {
                    error(XorStr("Pattern checksum query failed."));
                }
            }
            else {
                const DWORD guardMask = PAGE_GUARD | PAGE_NOACCESS;
                if ((mbi.Protect & guardMask) != 0) {
                    if (++patternFailures >= kPatternFailThreshold) {
                        error(XorStr("Pattern checksum read blocked."));
                    }
                }
                else {
                    const BYTE instruction = *reinterpret_cast<BYTE*>(Function_Address);
                    if (instruction == 0xE9 || instruction == 0xCC) {
                        error(XorStr("Pattern checksum failed, don't tamper with the program."));
                    }
                    patternFailures = 0;
                }
            }
        }

        Sleep(kLoopSleepMs);
    }
}

// Clean up seed data (file and registry key)
void cleanUpSeedData(const std::string& seed) {

    // Clean up the seed file
    std::string file_path = "C:\\ProgramData\\" + seed;
    if (std::filesystem::exists(file_path)) {
        std::filesystem::remove(file_path);
    }

    // Clean up the seed registry entry
    std::string regPath = "Software\\" + seed;
    RegDeleteKeyA(HKEY_CURRENT_USER, regPath.c_str()); 
}
