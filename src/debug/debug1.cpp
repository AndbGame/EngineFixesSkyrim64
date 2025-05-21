#include "debug.h"

#include <detours/detours.h>

namespace debug
{

    // example write_call
    struct example
    {
        static void thunk(RE::BSFaceGenNiNode* bSFaceGenNiNode)
        {
            if (bSFaceGenNiNode->GetUserData())
            {
                logger::info("Start UpdateMorphingJob for "sv, bSFaceGenNiNode->GetUserData()->GetFormID(), bSFaceGenNiNode->GetUserData()->GetName());
            }
            else {
                logger::info("Start UpdateMorphingJob for nullptr"sv);
            }

            func(bSFaceGenNiNode);

            if (bSFaceGenNiNode->GetUserData())
            {
                logger::info("End UpdateMorphingJob for "sv, bSFaceGenNiNode->GetUserData()->GetFormID(), bSFaceGenNiNode->GetUserData()->GetName());
            }
        }
        static inline REL::Relocation<decltype(thunk)> func;

        static inline void Install()
        {

            auto& trampoline = SKSE::GetTrampoline();
            //SKSE::AllocTrampoline(14);
            func = trampoline.write_call<5>(REL::Relocation<std::uintptr_t>(REL::ID(69378)).address(), thunk);

            logger::info("UpdateMorphingJob installed"sv);
        }
    };

    // 
    struct UpdateMorphingJob
    {
        typedef void(WINAPI* funcType)(RE::BSFaceGenNiNode* bSFaceGenNiNode);

        static void UpdateMorphingJobDetour(RE::BSFaceGenNiNode* bSFaceGenNiNode)
        {
            if (bSFaceGenNiNode->GetUserData())
            {
                logger::info("Start UpdateMorphingJob for <{:08X}:{}>"sv, bSFaceGenNiNode->GetUserData()->GetFormID(), bSFaceGenNiNode->GetUserData()->GetName());
            }
            else
            {
                logger::info("Start UpdateMorphingJob for nullptr"sv);
            }

            func(bSFaceGenNiNode);

            if (bSFaceGenNiNode->GetUserData())
            {
                logger::info("End UpdateMorphingJob for <{:08X}:{}>"sv, bSFaceGenNiNode->GetUserData()->GetFormID(), bSFaceGenNiNode->GetUserData()->GetName());
            }
        }
        static inline funcType func;

        static inline void Install()
        {

            const uintptr_t func_addr = REL::Relocation<std::uintptr_t>(REL::ID(26999)).address();
            func = (funcType)func_addr;

            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)func, (PBYTE)&UpdateMorphingJobDetour);

            if (DetourTransactionCommit() == NO_ERROR)
            {
                logger::info("UpdateMorphingJob installed");
            }
            else
            {
                logger::info("Failed to install UpdateMorphingJob");
            }
        }
    };

    void UpdateMorphingJobInstall()
    {
        //UpdateMorphingJob::Install();
    }
}
