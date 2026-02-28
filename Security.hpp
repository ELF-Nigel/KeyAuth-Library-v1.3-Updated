#pragma once
#include <Windows.h>
#include <string>
#include <accctrl.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <vector>

// code submitted in pull request from https://github.com/sbtoonz, authored by KeePassXC https://github.com/keepassxreboot/keepassxc/blob/dab7047113c4ad4ffead944d5c4ebfb648c1d0b0/src/core/Bootstrap.cpp#L121
inline bool LockMemAccess()
{
    // safer token/ACL setup and cleanup path -nigel
    HANDLE hToken = nullptr;
    DWORD cbBufferSize = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!GetTokenInformation(hToken, TokenUser, nullptr, 0, &cbBufferSize) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return false;
    }

    std::vector<BYTE> tokenUserBuffer(cbBufferSize);
    auto* pTokenUser = reinterpret_cast<PTOKEN_USER>(tokenUserBuffer.data());
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, cbBufferSize, &cbBufferSize)) {
        CloseHandle(hToken);
        return false;
    }

    if (!IsValidSid(pTokenUser->User.Sid)) {
        CloseHandle(hToken);
        return false;
    }

    const DWORD sidLength = GetLengthSid(pTokenUser->User.Sid);
    const DWORD cbACL = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + sidLength - sizeof(DWORD);
    std::vector<BYTE> aclBuffer(cbACL);
    auto* pACL = reinterpret_cast<PACL>(aclBuffer.data());
    if (!InitializeAcl(pACL, cbACL, ACL_REVISION)) {
        CloseHandle(hToken);
        return false;
    }

    if (!AddAccessAllowedAce(
        pACL,
        ACL_REVISION,
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
        pTokenUser->User.Sid)) {
        CloseHandle(hToken);
        return false;
    }

    const bool success = (ERROR_SUCCESS == SetSecurityInfo(
        GetCurrentProcess(),
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr, nullptr,
        pACL,
        nullptr));

    CloseHandle(hToken);
    return success;
}
