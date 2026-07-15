
#include <MinHook.h>

#include <FunctionHook.hpp>
#include <TiltedCore/StackAllocator.hpp>
#include <Memory.hpp>

#define RtlOffsetToPointer(Base, Offset) ((PCHAR)(((PCHAR)(Base)) + ((ULONG_PTR)(Offset))))

namespace TiltedPhoques
{
    FunctionHook::FunctionHook() noexcept
        : m_ppDetourFunction(nullptr)
        , m_pSystemFunction(nullptr)
        , m_pHookFunction(nullptr)
    {
    }

    FunctionHook::FunctionHook(void** appSystemFunction, void* apHookFunction) noexcept
        : m_ppDetourFunction(appSystemFunction)
        , m_pSystemFunction(*appSystemFunction)
        , m_pHookFunction(apHookFunction)
    {
    }

    FunctionHook::~FunctionHook() noexcept
    {
        if (m_ownsHook)
        {
            MH_DisableHook(m_pSystemFunction);
            MH_RemoveHook(m_pSystemFunction);
            if (m_ppDetourFunction)
                *m_ppDetourFunction = m_pSystemFunction;
            m_ownsHook = false;
        }
    }

    FunctionHook::FunctionHook(FunctionHook&& aRhs) noexcept
        : FunctionHook()
    {
        this->operator=(std::move(aRhs));
    }

    FunctionHook& FunctionHook::operator=(FunctionHook&& aRhs) noexcept
    {
        std::swap(m_ppDetourFunction, aRhs.m_ppDetourFunction);
        std::swap(m_pSystemFunction, aRhs.m_pSystemFunction);
        std::swap(m_pHookFunction, aRhs.m_pHookFunction);
        std::swap(m_ownsHook, aRhs.m_ownsHook);

        return *this;
    }

    FunctionHookManager::FunctionHookManager() noexcept
    {
        MH_Initialize();
    }

    FunctionHookManager::~FunctionHookManager() noexcept
    {
        UninstallHooks();

        MH_Uninitialize();
    }

    HookInstallSummary FunctionHookManager::InstallDelayedHooks() noexcept
    {
        if (m_installSummary.Failures != 0)
        {
            OutputDebugStringA("SkyrimTogetherVR: rolling back hooks after an earlier MinHook failure.\n");
            UninstallHooks();
            m_delayedHooks.clear();
            return m_installSummary;
        }

        for (auto& hook : m_delayedHooks)
        {
            ++m_installSummary.DelayedAttempted;
            const auto createStatus = MH_CreateHook(hook.m_pSystemFunction, hook.m_pHookFunction, hook.m_ppDetourFunction);
            if (createStatus != MH_OK)
            {
                ++m_installSummary.Failures;
                OutputDebugStringA("SkyrimTogetherVR: delayed MinHook creation failed.\n");
                break;
            }

            const auto enableStatus = MH_EnableHook(hook.m_pSystemFunction);
            if (enableStatus != MH_OK)
            {
                MH_RemoveHook(hook.m_pSystemFunction);
                ++m_installSummary.Failures;
                OutputDebugStringA("SkyrimTogetherVR: delayed MinHook enable failed.\n");
                break;
            }

            hook.m_ownsHook = true;
            m_installedHooks.emplace_back(std::move(hook));
            ++m_installSummary.DelayedInstalled;
        }

        m_delayedHooks.clear();
        if (m_installSummary.Failures != 0)
        {
            OutputDebugStringA("SkyrimTogetherVR: rolling back all hooks after a delayed MinHook failure.\n");
            UninstallHooks();
        }
        return m_installSummary;
    }

    void FunctionHookManager::UninstallHooks() noexcept
    {
        for (auto it = m_installedHooks.rbegin(); it != m_installedHooks.rend(); ++it)
        {
            auto& hook = *it;
            if (!hook.m_ownsHook)
                continue;

            MH_DisableHook(hook.m_pSystemFunction);
            MH_RemoveHook(hook.m_pSystemFunction);
            if (hook.m_ppDetourFunction)
                *hook.m_ppDetourFunction = hook.m_pSystemFunction;
            hook.m_ownsHook = false;
        }

        m_installedHooks.clear();

        for (auto it = m_iatHooks.rbegin(); it != m_iatHooks.rend(); ++it)
        {
            auto& iatHook = *it;
            const vp::ScopedContext thunkMemory(iatHook.pThunk, sizeof(iatHook.pThunk));
            thunkMemory.Write(iatHook.pOriginal);
        }
        m_iatHooks.clear();
    }

    void FunctionHookManager::Add(FunctionHook aFunctionHook, const bool aDelayed) noexcept
    {
        if (aDelayed)
            m_delayedHooks.emplace_back(std::move(aFunctionHook));
        else
        {
            ++m_installSummary.ImmediateAttempted;
            const auto createStatus = MH_CreateHook(aFunctionHook.m_pSystemFunction, aFunctionHook.m_pHookFunction, aFunctionHook.m_ppDetourFunction);
            if (createStatus != MH_OK)
            {
                ++m_installSummary.Failures;
                OutputDebugStringA("SkyrimTogetherVR: immediate MinHook creation failed.\n");
                return;
            }

            const auto enableStatus = MH_EnableHook(aFunctionHook.m_pSystemFunction);
            if (enableStatus != MH_OK)
            {
                MH_RemoveHook(aFunctionHook.m_pSystemFunction);
                ++m_installSummary.Failures;
                OutputDebugStringA("SkyrimTogetherVR: immediate MinHook enable failed.\n");
                return;
            }

            aFunctionHook.m_ownsHook = true;
            m_installedHooks.emplace_back(std::move(aFunctionHook));
            ++m_installSummary.ImmediateInstalled;
        }
    }

    void* FunctionHookManager::Add(void* apFunctionDetour, const char* acpLibraryName, const char* acpMethod) noexcept
    {
        const auto pRealFunctionThunk = GetImportedFunction(nullptr, acpLibraryName, acpMethod);

        if (!pRealFunctionThunk)
            return nullptr;

        const auto pRealFunction = *pRealFunctionThunk;

        const vp::ScopedContext thunkMemory(pRealFunctionThunk, sizeof(void*));
        thunkMemory.Write(apFunctionDetour);

        m_iatHooks.emplace_back(IATHook{ pRealFunctionThunk, pRealFunction });

        return pRealFunction;
    }

    void** GetImportedFunction(const wchar_t *acpModuleName, const char* acpLibraryName, const char* acpMethod) noexcept
    {
        const auto pBase = GetModuleHandleW(acpModuleName);

        const auto pImageDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pBase);
        auto pImageNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(RtlOffsetToPointer(pBase, pImageDosHeader->e_lfanew));

        const auto pVirtualAddress = pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

        for (auto pImageImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(RtlOffsetToPointer(pBase, pVirtualAddress)); pImageImportDescriptor->Name; ++pImageImportDescriptor)
        {
            const auto pLibraryName = reinterpret_cast<const char*>RtlOffsetToPointer(pBase, pImageImportDescriptor->Name);

            if (!_stricmp(pLibraryName, acpLibraryName))
            {
                auto pImportAddressTable = reinterpret_cast<uintptr_t*>(RtlOffsetToPointer(pBase, pImageImportDescriptor->FirstThunk));
                auto pImageThunkData = reinterpret_cast<IMAGE_THUNK_DATA*>(RtlOffsetToPointer(pBase, pImageImportDescriptor->OriginalFirstThunk));

                while (const auto pOrdinal = pImageThunkData->u1.Ordinal)
                {
                    const auto pFunctionName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(RtlOffsetToPointer(pBase, pImageThunkData->u1.AddressOfData))->Name;

                    if (IMAGE_SNAP_BY_ORDINAL(pOrdinal))
                    {
                        // Skip ordinal functions, we just want named functions
                    }
                    else if (!_stricmp(pFunctionName, acpMethod))
                    {
                        return reinterpret_cast<void**>(pImportAddressTable);
                    }

                    ++pImageThunkData;
                    ++pImportAddressTable;
                }

                return nullptr;
            }
        }

        return nullptr;
    }
}
