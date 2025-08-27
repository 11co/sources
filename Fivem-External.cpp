#include <Windows.h>
#include <thread>
#include <future>
#include <Cheat/Cheat.hpp>
#include <FrameWork/FrameWork.hpp>
#include <tchar.h>
#include "xor.hpp"
#include "../Fivem-External/Auth/auth.hpp"
#include "../Fivem-External/FrameWork/Render/Interface.hpp"
#include <iostream> // Add iostream for printing output

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

int main()
{
    SetConsoleTitleA(("VacBan"));
    std::string licensekey;

    std::cout << "[INFO] Starting VacBan Console..." << std::endl;

    std::cout << "[INFO] Sucess authentication, Injeting in moments..." << std::endl;

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