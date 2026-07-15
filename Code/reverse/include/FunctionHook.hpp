#pragma once

#include <Windows.h>

#include <cstddef>

#include <TiltedCore/Stl.hpp>
#include <Memory.hpp>

namespace TiltedPhoques
{
    void** GetImportedFunction(const wchar_t* acpModuleName, const char* acpLibraryName, const char* acpMethod) noexcept;

    struct FunctionHook
    {
        FunctionHook() noexcept;
        explicit FunctionHook(void** appSystemFunction, void* apHookFunction) noexcept;
        ~FunctionHook() noexcept;
        FunctionHook(const FunctionHook& acRhs) = delete;
        FunctionHook(FunctionHook&& aRhs) noexcept;
        FunctionHook& operator=(const FunctionHook& acRhs) = delete;
        FunctionHook& operator=(FunctionHook&& aRhs) noexcept;

    protected:

        friend class FunctionHookManager;

        void** m_ppDetourFunction;
        void* m_pSystemFunction;
        void* m_pHookFunction;
        bool m_ownsHook{false};
    };

    struct HookInstallSummary
    {
        std::size_t DelayedAttempted{};
        std::size_t DelayedInstalled{};
        std::size_t ImmediateAttempted{};
        std::size_t ImmediateInstalled{};
        std::size_t Failures{};
    };

    class FunctionHookManager
    {
    protected:

        struct IATHook
        {
            void** pThunk;
            void* pOriginal;
        };

    public:

        FunctionHookManager(const FunctionHookManager&) = delete;
        FunctionHookManager(FunctionHookManager&&) = delete;

        FunctionHookManager& operator=(const FunctionHookManager&) = delete;
        FunctionHookManager& operator=(FunctionHookManager&&) = delete;

        HookInstallSummary InstallDelayedHooks() noexcept;
        void UninstallHooks() noexcept;

        void Add(FunctionHook aFunctionHook, bool aDelayed = false) noexcept;
        void* Add(void* apFunctionDetour, const char* acpLibraryName, const char* acpMethod) noexcept;

        template<class T, class U>
        void Add(T** aSystemFunction, U* aHookFunction, bool aDelayed = false) noexcept
        {
            Add(FunctionHook(reinterpret_cast<void**>(aSystemFunction), reinterpret_cast<void*>(aHookFunction)), aDelayed);
        }

        template<class T>
        void* AddSystem(const std::string& acLibraryName, const std::string& acFunctionName, T* apFunction) noexcept
        {
            const auto module = LoadLibraryA(acLibraryName.c_str());
            if (module != nullptr)
            {
                const auto pTargetFunction = reinterpret_cast<void*>(GetProcAddress(module, acFunctionName.c_str()));
                if (pTargetFunction == nullptr)
                    return nullptr;

                auto pSystemFunction = pTargetFunction;
                const auto installedCount = m_installedHooks.size();
                Add(&pSystemFunction, apFunction, false);

                // AddSystem returns the trampoline through a local variable. Do
                // not retain its stack address as a restoration destination.
                if (m_installedHooks.size() == installedCount + 1)
                {
                    auto& hook = m_installedHooks.back();
                    if (hook.m_pSystemFunction == pTargetFunction && hook.m_ppDetourFunction == &pSystemFunction)
                        hook.m_ppDetourFunction = nullptr;
                }

                return pSystemFunction;
            }

            return nullptr;
        }

        static FunctionHookManager& GetInstance() noexcept
        {
            static FunctionHookManager s_instance;
            return s_instance;
        }

    private:

        FunctionHookManager() noexcept;
        ~FunctionHookManager() noexcept;

        Vector<FunctionHook> m_delayedHooks;
        Vector<FunctionHook> m_installedHooks;
        Vector<IATHook> m_iatHooks;
        HookInstallSummary m_installSummary;
    };

    template<class T, class Func>
    Func HookVTable(T* pInstance, const size_t aIndex, Func aFunctionPtr)
    {
        auto pVTable = *reinterpret_cast<uintptr_t * *>(pInstance);
        Func pRealFunction = reinterpret_cast<Func>(pVTable[aIndex]);

        const vp::ScopedContext memory(&pVTable[aIndex], sizeof(&pVTable[aIndex]));
        memory.Write(aFunctionPtr);

        return pRealFunction;
    }
}

#define TP_HOOK(systemFunction, hookFunction) TiltedPhoques::FunctionHookManager::GetInstance().Add(systemFunction, hookFunction, true)
#define TP_HOOK_IMMEDIATE(systemFunction, hookFunction) TiltedPhoques::FunctionHookManager::GetInstance().Add(systemFunction, hookFunction, false)

#define TP_HOOK_SYSTEM(libraryName, functionName, hookFunction) TiltedPhoques::FunctionHookManager::GetInstance().AddSystem(libraryName, functionName, hookFunction)
#define TP_HOOK_IAT(functionName, libraryName) Real ##functionName = (T ##functionName)TiltedPhoques::FunctionHookManager::GetInstance().Add(Hook ## functionName, libraryName, #functionName)
#define TP_HOOK_IAT2(libraryName, functionName, hook) TiltedPhoques::FunctionHookManager::GetInstance().Add(reinterpret_cast<void*>(&hook), libraryName, functionName)

#define TP_HOOK_COMMIT TiltedPhoques::FunctionHookManager::GetInstance().InstallDelayedHooks();


#define TP_EMPTY_HOOK_PLACEHOLDER \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop(); \
__nop();
