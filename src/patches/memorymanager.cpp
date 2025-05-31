#include "version.h"

#include "offsets.h"
#include <rpmalloc.h>
#include <mutex>

namespace
{
    std::byte* g_trash{ nullptr };  // a dumb workaround for reads from/writes to zero size allocations

    namespace detail
    {
        struct asm_patch :
            Xbyak::CodeGenerator
        {
            asm_patch(std::uintptr_t a_dst)
            {
                mov(rax, a_dst);
                jmp(rax);
            }
        };
    }

    void asm_jump(std::uintptr_t a_from, [[maybe_unused]] std::size_t a_size, std::uintptr_t a_to)
    {
        detail::asm_patch p{ a_to };
        p.ready();
        assert(p.getSize() <= a_size);
        REL::safe_write(
            a_from,
            std::span{ p.getCode<const std::byte*>(), p.getSize() });
    }

    namespace AutoScrapBuffer
    {
        void Ctor()
        {
            REL::Relocation<std::uintptr_t> target{ offsets::MemoryManager::AutoScrapBuffer_Ctor, 0x1D };
            constexpr std::size_t size = 0x32 - 0x1D;
            REL::safe_fill(target.address(), REL::NOP, size);
        }

        void Dtor()
        {
            REL::Relocation<std::uintptr_t> base{ offsets::MemoryManager::AutoScrapBuffer_Dtor };

            {
                struct Patch :
                    Xbyak::CodeGenerator
                {
                    Patch()
                    {
                        xor_(rax, rax);
                        cmp(rbx, rax);
                    }
                };

                const auto dst = base.address() + 0x12;
                constexpr std::size_t size = 0x2F - 0x12;
                REL::safe_fill(dst, REL::NOP, size);

                Patch p;
                p.ready();
                assert(p.getSize() <= size);
                REL::safe_write(
                    dst,
                    stl::span{ p.getCode<const std::byte*>(), p.getSize() });
            }

            {
                const auto dst = base.address() + 0x2F;
                REL::safe_write(dst, std::uint8_t{ 0x74 });  // jnz -> jz
            }
        }

        void Install()
        {
            Ctor();
            Dtor();
        }
    }

#if ENABLE_STATISTICS
    namespace MemoryManagerStats
    {
        struct
        {
            struct
            {
                std::chrono::nanoseconds total = 0ns;
                unsigned long count = 0;
                std::mutex mutex;
            } Allocate;
            struct
            {
                std::chrono::nanoseconds total = 0ns;
                unsigned long count = 0;
                std::mutex mutex;
            } Deallocate;
            struct
            {
                std::chrono::nanoseconds total = 0ns;
                unsigned long count = 0;
                std::mutex mutex;
            } Reallocate;
        } Stats;
    }
#endif

    namespace MemoryManager
    {
        void* Allocate(RE::MemoryManager*, std::size_t a_size, std::uint32_t a_alignment, bool a_alignmentRequired)
        {
            void* ret = g_trash;
#if ENABLE_STATISTICS
            auto start = std::chrono::steady_clock::now();
#endif
            //logger::info("MemoryManager::Allocate START");
            if (a_size > 0)
            {
                //rpmalloc_thread_initialize();
                ret = a_alignmentRequired ?
                          rpaligned_alloc(a_alignment, a_size) :  // rpaligned_alloc(a_alignment, a_size) :  // scalable_aligned_malloc(a_size, a_alignment)
                          rpmalloc(a_size);                       // rpmalloc(a_size);                       // scalable_malloc(a_size)
            }
            //logger::info("MemoryManager::Allocate END");
            if (ret == 0) {
                logger::error("MemoryManager::Allocate ret: 0; a_size: {}, a_alignment: {}, a_alignmentRequired: {}"sv, a_size, a_alignment, a_alignmentRequired);
            }
#if ENABLE_STATISTICS
            std::lock_guard<std::mutex> guard(MemoryManagerStats::Stats.Allocate.mutex);
            auto end = std::chrono::steady_clock::now();
            if (MemoryManagerStats::Stats.Allocate.count < (ULONG_MAX - 10)) {
                MemoryManagerStats::Stats.Allocate.count++;
                MemoryManagerStats::Stats.Allocate.total += end - start;
            }
#endif
            return ret;
        }

        void Deallocate(RE::MemoryManager*, void* a_mem, bool a_alignmentRequired)
        {
#if ENABLE_STATISTICS
            auto start = std::chrono::steady_clock::now();
#endif
            //logger::info("MemoryManager::Deallocate START");
            if (a_mem != g_trash)
                //rpmalloc_thread_initialize();
                a_alignmentRequired ?
                    rpfree(a_mem) :        //rpfree(a_mem) : // scalable_aligned_free(a_mem)
                    rpfree(a_mem);   // rpfree(a_mem); // scalable_free(a_mem)
            //logger::info("MemoryManager::Deallocate END");
#if ENABLE_STATISTICS
            std::lock_guard<std::mutex> guard(MemoryManagerStats::Stats.Deallocate.mutex);
            auto end = std::chrono::steady_clock::now();
            if (MemoryManagerStats::Stats.Deallocate.count < (ULONG_MAX - 10))
            {
                MemoryManagerStats::Stats.Deallocate.count++;
                MemoryManagerStats::Stats.Deallocate.total += end - start;
            }
#endif
        }

        void* Reallocate(RE::MemoryManager* a_self, void* a_oldMem, std::size_t a_newSize, std::uint32_t a_alignment, bool a_alignmentRequired)
        {
            void* ret = g_trash;
#if ENABLE_STATISTICS
            auto start = std::chrono::steady_clock::now();
#endif
            //logger::info("MemoryManager::Reallocate START");
            if (a_oldMem == g_trash)
                ret = Allocate(a_self, a_newSize, a_alignment, a_alignmentRequired);
            else
            {
                //rpmalloc_thread_initialize();
                ret = a_alignmentRequired ?
                          rpaligned_realloc(a_oldMem, a_alignment, a_newSize, rpmalloc_usable_size(a_oldMem), 0) :  //rpaligned_realloc(a_oldMem, a_alignment, a_newSize, rpmalloc_usable_size(a_oldMem), 0) : //scalable_aligned_realloc(a_oldMem, a_newSize, a_alignment) :
                          rprealloc(a_oldMem, a_newSize);                                                           //rprealloc(a_oldMem, a_newSize);                  // scalable_realloc(a_oldMem, a_newSize);
            }

            //logger::info("MemoryManager::Reallocate END");
            if (ret == 0)
            {
                logger::error("MemoryManager::Reallocate ret: 0; a_newSize: {}, a_alignment: {}, a_alignmentRequired: {}"sv, a_newSize, a_alignment, a_alignmentRequired);
            }
#if ENABLE_STATISTICS
            std::lock_guard<std::mutex> guard(MemoryManagerStats::Stats.Reallocate.mutex);
            auto end = std::chrono::steady_clock::now();
            if (MemoryManagerStats::Stats.Reallocate.count < (ULONG_MAX - 10))
            {
                MemoryManagerStats::Stats.Reallocate.count++;
                MemoryManagerStats::Stats.Reallocate.total += end - start;
            }
#endif
            return ret;
        }

        void ReplaceAllocRoutines()
        {
            using tuple_t = std::tuple<REL::ID, std::size_t, void*>;
            const std::array todo{
                tuple_t{ offsets::MemoryManager::MemoryManager_Allocate, 0x248, &Allocate },
                tuple_t{ offsets::MemoryManager::MemoryManager_DeAllocate, 0x114, &Deallocate },
                tuple_t{ offsets::MemoryManager::MemoryManager_ReAllocate, 0x1F6, &Reallocate },
            };

            for (const auto& [offset, size, func] : todo)
            {
                REL::Relocation<std::uintptr_t> target{ offset };
                REL::safe_fill(target.address(), REL::INT3, size);
                asm_jump(target.address(), size, reinterpret_cast<std::uintptr_t>(func));
            }
        }

        void StubInit()
        {
            REL::Relocation<std::uintptr_t> target{ offsets::MemoryManager::MemoryManager_Init };
            REL::safe_fill(target.address(), REL::INT3, 0x1A7);
            REL::safe_write(target.address(), REL::RET);
        }

        void Install()
        {
            StubInit();
            ReplaceAllocRoutines();
            RE::MemoryManager::GetSingleton()->RegisterMemoryManager();
            RE::BSThreadEvent::InitSDM();
        }
    }

    namespace msize
    {
        std::size_t hk_msize(void* a_ptr)
        {
            logger::info("msize::hk_msize START");
            //rpmalloc_thread_initialize();
            //return scalable_msize(a_ptr);
            auto a = rpmalloc_usable_size(a_ptr);
            logger::info("msize::hk_msize END");
            return a;
        }

        void Install()
        {
            SKSE::PatchIAT(hk_msize, "API-MS-WIN-CRT-HEAP-L1-1-0.DLL", "_msize");
        }
    }

    namespace ScrapHeap
    {
        void* Allocate(RE::ScrapHeap*, std::size_t a_size, std::size_t a_alignment)
        {
            //logger::info("ScrapHeap::Allocate START");
            //rpmalloc_thread_initialize();
            void* ret = a_size > 0 ?
                       rpaligned_alloc(a_alignment, a_size) : // scalable_aligned_malloc(a_size, a_alignment) :
                            g_trash;
            //logger::info("ScrapHeap::Allocate END");

            if (ret == 0)
            {
                logger::error("ScrapHeap::Allocate ret: 0; a_size: {}, a_alignment: {}"sv, a_size, a_alignment);
            }
            return ret;
        }

        RE::ScrapHeap* Ctor(RE::ScrapHeap* a_this)
        {
            std::memset(a_this, 0, sizeof(RE::ScrapHeap));
            reinterpret_cast<std::uintptr_t*>(a_this)[0] = offsets::MemoryManager::ScrapHeap_vtbl.address();
            return a_this;
        }

        void Deallocate(RE::ScrapHeap*, void* a_mem)
        {
            //rpmalloc_thread_initialize();
            //logger::info("ScrapHeap::Deallocate START");
            if (a_mem != g_trash)
                rpfree(a_mem);  // scalable_aligned_free(a_mem);
            //logger::info("ScrapHeap::Deallocate END");
                
        }

        void WriteHooks()
        {
            using tuple_t = std::tuple<REL::ID, std::size_t, void*>;
            const std::array todo{
                tuple_t{ offsets::MemoryManager::ScrapHeap_Allocate, 0x5E7, &Allocate },
                tuple_t{ offsets::MemoryManager::ScrapHeap_DeAllocate, 0x13E, &Deallocate },
                tuple_t{ offsets::MemoryManager::ScrapHeap_ctor, 0x13A, &Ctor },
            };

            for (const auto& [offset, size, func] : todo)
            {
                REL::Relocation<std::uintptr_t> target{ offset };
                REL::safe_fill(target.address(), REL::INT3, size);
                asm_jump(target.address(), size, reinterpret_cast<std::uintptr_t>(func));
            }
        }

        void WriteStubs()
        {
            using tuple_t = std::tuple<REL::ID, std::size_t>;
            const std::array todo{
                tuple_t{ offsets::MemoryManager::ScrapHeap_Clean, 0xBA },           // Clean
                tuple_t{ offsets::MemoryManager::ScrapHeap_ClearKeepPages, 0x8 },   // ClearKeepPages
                tuple_t{ offsets::MemoryManager::ScrapHeap_InsertFreeBlock, 0xF6 }, // InsertFreeBlock
                tuple_t{ offsets::MemoryManager::ScrapHeap_RemoveFreeBlock, 0x185 },  // RemoveFreeBlock
                tuple_t{ offsets::MemoryManager::ScrapHeap_SetKeepPages, 0x4 },    // SetKeepPages
                tuple_t{ offsets::MemoryManager::ScrapHeap_Dtor, 0x32 },   // dtor
            };

            for (const auto& [offset, size] : todo)
            {
                REL::Relocation<std::uintptr_t> target{ offset };
                REL::safe_fill(target.address(), REL::INT3, size);
                REL::safe_write(target.address(), REL::RET);
            }
        }

        void Install()
        {
            WriteStubs();
            WriteHooks();
        }
    }
}

namespace patches
{

    void ErrorCallback(const char* message)
    {
        logger::error("MemoryManager::Error {}"sv, message);
        throw message;
    }

    bool PatchMemoryManager()
    {
        logger::trace("- memory manager patch -"sv);

        g_trash = new std::byte[1u << 10]{ static_cast<std::byte>(0) };

        //rpmalloc_config_t config{};
        //config.error_callback = &ErrorCallback;

        //rpmalloc_initialize_config(&config);

        AutoScrapBuffer::Install();
        MemoryManager::Install();
        msize::Install();
        ScrapHeap::Install();

        logger::trace("success"sv);
        return true;
    }

    void WriteMemoryManagerStats()
    {
#if ENABLE_STATISTICS
        std::lock_guard<std::mutex> guard(MemoryManagerStats::Stats.Allocate.mutex);
        std::lock_guard<std::mutex> guard1(MemoryManagerStats::Stats.Deallocate.mutex);
        std::lock_guard<std::mutex> guard2(MemoryManagerStats::Stats.Reallocate.mutex);
        
        logger::trace("Allocate:   {} ns. Total: {} ns, Count: {}"sv, (MemoryManagerStats::Stats.Allocate.total / MemoryManagerStats::Stats.Allocate.count).count(), MemoryManagerStats::Stats.Allocate.total.count(), MemoryManagerStats::Stats.Allocate.count);
        logger::trace("Deallocate: {} ns. Total: {} ns, Count: {}"sv, (MemoryManagerStats::Stats.Deallocate.total / MemoryManagerStats::Stats.Deallocate.count).count(), MemoryManagerStats::Stats.Deallocate.total.count(), MemoryManagerStats::Stats.Deallocate.count);
        logger::trace("Reallocate: {} ns. Total: {} ns, Count: {}"sv, (MemoryManagerStats::Stats.Reallocate.total / MemoryManagerStats::Stats.Reallocate.count).count(), MemoryManagerStats::Stats.Reallocate.total.count(), MemoryManagerStats::Stats.Reallocate.count);
#endif
    }
}
