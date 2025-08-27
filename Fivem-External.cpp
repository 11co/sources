#include <Windows.h>
#include <thread>
#include <future>
#include <Cheat/Cheat.hpp>
#include <FrameWork/FrameWork.hpp>
#include <tchar.h>
#include "xor.hpp"
#include "../Fivem-External/FrameWork/Render/Interface.hpp"
#include <iostream>
#include <wininet.h>

static BOOL CheckForUIAccess(DWORD* pdwErr, BOOL* pfUIAccess)
{
    BOOL result = FALSE;
    HANDLE hToken;

    std::cout << "[DEBUG] Checking for UI Access..." << std::endl;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        std::cout << "[DEBUG] OpenProcessToken succeeded." << std::endl;
        DWORD dwRetLen;

        if (GetTokenInformation(hToken, TokenUIAccess, pfUIAccess, sizeof(*pfUIAccess), &dwRetLen))
        {
            std::cout << "[DEBUG] GetTokenInformation succeeded. UIAccess: " << (*pfUIAccess ? "TRUE" : "FALSE") << std::endl;
            result = TRUE;
        }
        else
        {
            *pdwErr = GetLastError();
            std::cout << "[DEBUG] GetTokenInformation failed. Error: " << *pdwErr << std::endl;
        }
        CloseHandle(hToken);
    }
    else
    {
        *pdwErr = GetLastError();
        std::cout << "[DEBUG] OpenProcessToken failed. Error: " << *pdwErr << std::endl;
    }

    return result;
}

DWORD WINAPI Unload()
{
    std::cout << "[DEBUG] Unloading and calling ExitProcess." << std::endl;
    SafeCall(ExitProcess)(0);
    return TRUE;
}

bool CheckLicense(const std::string& key)
{
    HINTERNET hInternet = InternetOpenA("AuthCheck", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return false;

    std::string url = "http://porna.shop/check.php?key=" + key;
    HINTERNET hFile = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        InternetCloseHandle(hInternet);
        return false;
    }

    char buffer[512] = { 0 };
    DWORD bytesRead = 0;
    InternetReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead);
    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    std::string response(buffer);
    if (response.find("Auth Successful") != std::string::npos) {
        std::cout << "[INFO] License verified successfully!" << std::endl;
        return true;
    }

    std::cerr << "[ERROR] License verification failed!" << std::endl;
    return false;
}

int main()
{
    SetConsoleTitleA(("VacBan"));
    std::string licensekey;

    std::cout << "[INFO] Starting VacBan Console..." << std::endl;
    std::cout << "[INPUT] Enter your license key: ";
    std::cin >> licensekey;

    if (!CheckLicense(licensekey)) {
        std::cout << "[ERROR] Invalid license key. Exiting..." << std::endl;
        return 0; // Program kapanır
    }

    std::cout << "[INFO] Success authentication, Injecting in moments..." << std::endl;

    std::cout << "[INFO] Wait for your game to close by itself" << std::endl;

    std::cout << "[DEBUG] Initializing Cheat..." << std::endl;
    Cheat::Initialize();
    std::cout << "[DEBUG] Cheat Initialization complete." << std::endl;

    while (!g_Options.General.ShutDown)
    {
        std::cout << "[DEBUG] Main loop running. Waiting for shutdown signal..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::cout << "[DEBUG] Shutdown signal received. Exiting..." << std::endl;

    //std::cout << skCrypt("You have been unbanned.") << std::endl; Sleep(5000); exit(0);
}