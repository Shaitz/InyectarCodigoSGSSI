#include "pch.h"
#include <Windows.h>
#include <iostream>

void Patch(BYTE* dst, BYTE* src, unsigned int size)
{
    DWORD oldprotect;
    VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
    memcpy(dst, src, size);
    VirtualProtect(dst, size, oldprotect, &oldprotect);
}

DWORD WINAPI HackThread(LPVOID param)
{
    uintptr_t moduleBase = reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr));
    uintptr_t jmpFunction = moduleBase + 0x3D4C; // 0x3d4c = offset del jne 
    Patch((BYTE*)(moduleBase+0x3D4C), (BYTE*)"\x74", 1);

    FreeLibraryAndExitThread(reinterpret_cast<HMODULE>(param), 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    DisableThreadLibraryCalls(hModule);
    
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(HackThread), hModule, 0, nullptr);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

