#include "version.h"

#include "offsets.h"

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

    namespace MemoryManagerStats
    {

        struct PointerStats
        {
            int allocated = 0;
        };

        tbb::concurrent_hash_map<uintptr_t, PointerStats*> allocatedPointers;

        RE::TESForm* ctd;

        //std::mutex memory_mutex;

        void Allocate(void* mem)
        {
            //std::lock_guard<std::mutex> guard(memory_mutex);

            decltype(allocatedPointers)::accessor accessor;

            uintptr_t addr = reinterpret_cast<uintptr_t>(mem);

            if (allocatedPointers.find(accessor, addr))
            {
                PointerStats* stats = accessor->second;
                stats->allocated++;
                if (stats->allocated > 1)
                {
                    logger::trace("MemoryManagerStats::Allocate error 101: already allocated {} times for {}.", stats->allocated, addr);
                }
                else {
                    //logger::trace("MemoryManagerStats::Allocate success: allocated {} times for {}.", stats->allocated, addr);
                }
            }
            else
            {
                PointerStats* stats = new PointerStats();
                stats->allocated = 1;
                allocatedPointers.emplace(addr, stats);
                //logger::trace("MemoryManagerStats::Allocate success: allocated {} times for {}.", stats->allocated, addr);
            }
        }

        void Deallocate(void* mem)
        {
            //std::lock_guard<std::mutex> guard(memory_mutex);
            decltype(allocatedPointers)::accessor accessor;

            uintptr_t addr = reinterpret_cast<uintptr_t>(mem);

            if (allocatedPointers.find(accessor, addr))
            {
                PointerStats* stats = accessor->second;
                stats->allocated--;
                if (stats->allocated < 0)
                {
                    logger::trace("MemoryManagerStats::Deallocate error 202: already deallocated {} times for {}.", (stats->allocated * -1), addr);
                    std::this_thread::sleep_for(std::chrono::seconds(10000));

                }
                else {
                    //logger::trace("MemoryManagerStats::Deallocate success: allocated {} times for {}.", stats->allocated, addr);
                }
            }
            else
            {
                logger::trace("MemoryManagerStats::Deallocate error 203: not allocated for {}.", addr);
            }
        }

        void Reallocate(void* oldmem, void* newmem)
        {
            //std::lock_guard<std::mutex> guard(memory_mutex);
            decltype(allocatedPointers)::accessor accessor;

            uintptr_t old_addr = reinterpret_cast<uintptr_t>(oldmem);
            uintptr_t new_addr = reinterpret_cast<uintptr_t>(newmem);

            if (old_addr == new_addr) {
                return;
            }

            if (allocatedPointers.find(accessor, old_addr))
            {
                PointerStats* stats = accessor->second;
                stats->allocated--;
                if (stats->allocated < 0)
                {
                    logger::trace("MemoryManagerStats::Reallocate old_addr error 302: already deallocated {} times for {}.", (stats->allocated * -1), old_addr);
                }
                else
                {
                    //logger::trace("MemoryManagerStats::Reallocate old_addr success: allocated {} times for {}.", stats->allocated, old_addr);
                }
            }
            else
            {
                logger::trace("MemoryManagerStats::Reallocate old_addr error 303: not allocated for {}.", old_addr);
            }

            if (allocatedPointers.find(accessor, new_addr))
            {
                PointerStats* stats = accessor->second;
                stats->allocated++;
                if (stats->allocated > 1)
                {
                    logger::trace("MemoryManagerStats::Reallocate new_addr error 301: already allocated {} times for {}.", stats->allocated, new_addr);
                }
                else
                {
                    //logger::trace("MemoryManagerStats::Reallocate new_addr success: allocated {} times for {}.", stats->allocated, new_addr);
                }
            }
            else
            {
                PointerStats* stats = new PointerStats();
                stats->allocated = 1;
                allocatedPointers.emplace(new_addr, stats);
                //logger::trace("MemoryManagerStats::Reallocate new_addr success: allocated {} times for {}.", stats->allocated, new_addr);
            }
        }
    }

    namespace MemoryManager
    {
        void* Allocate(RE::MemoryManager*, std::size_t a_size, std::uint32_t a_alignment, bool a_alignmentRequired)
        {
            void* ret = g_trash;
            if (a_size > 0)
            {
                errno = 0;
                ret = a_alignmentRequired ?
                          scalable_aligned_malloc(a_size, a_alignment) :
                          scalable_malloc(a_size);
                if (errno || ret == nullptr)
                {
                    logger::trace("MemoryManager::Allocate error {} ", errno);
                }
                else
                {
                    MemoryManagerStats::Allocate(ret);
                }
            }
            return ret;
        }

        void Deallocate(RE::MemoryManager*, void* a_mem, bool a_alignmentRequired)
        {
            if (a_mem != g_trash && a_mem != nullptr)
            {
                errno = 0;
                if (scalable_msize(a_mem) != 0)
                {
                    MemoryManagerStats::Deallocate(a_mem);

                    a_alignmentRequired ?
                        scalable_aligned_free(a_mem) :
                        scalable_free(a_mem);

                }
                else
                {
                    logger::trace("MemoryManager::Deallocate trying to free already free pointer");
                }
                if (errno)
                {
                    logger::trace("MemoryManager::Deallocate error {} ", errno);
                }
            }
        }

        void* Reallocate(RE::MemoryManager* a_self, void* a_oldMem, std::size_t a_newSize, std::uint32_t a_alignment, bool a_alignmentRequired)
        {
            void* ret = g_trash;
            if (a_oldMem == g_trash)
                ret = Allocate(a_self, a_newSize, a_alignment, a_alignmentRequired);
            else
            {
                errno = 0;
                ret = a_alignmentRequired ?
                           scalable_aligned_realloc(a_oldMem, a_newSize, a_alignment) :
                           scalable_realloc(a_oldMem, a_newSize);
                if (errno || ret == nullptr)
                {
                    logger::trace("MemoryManager::Reallocate error {} ", errno);
                }
                else {
                    MemoryManagerStats::Reallocate(a_oldMem, ret);
                }
            }
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
            return scalable_msize(a_ptr);
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
            void* ret = g_trash;
            if (a_size > 0)
            {
                errno = 0;
                ret = scalable_aligned_malloc(a_size, a_alignment);
                if (errno || ret == nullptr)
                {
                    logger::trace("ScrapHeap::Allocate error {} ", errno);
                }
                else
                {
                    MemoryManagerStats::Allocate(ret);
                }
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
            if (a_mem != g_trash && a_mem != nullptr)
            {
                errno = 0;
                if (scalable_msize(a_mem) != 0)
                {
                    scalable_aligned_free(a_mem);

                    MemoryManagerStats::Deallocate(a_mem);
                }
                else
                {
                    logger::trace("ScrapHeap::Deallocate trying to free already free pointer");
                }
                if (errno)
                {
                    logger::trace("ScrapHeap::Deallocate error {} ", errno);
                }
            }
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
    bool PatchMemoryManager()
    {
        logger::trace("- memory manager patch -"sv);

        g_trash = new std::byte[1u << 10]{ static_cast<std::byte>(0) };

        AutoScrapBuffer::Install();
        MemoryManager::Install();
        msize::Install();
        ScrapHeap::Install();

        logger::trace("success"sv);
        return true;
    }
}
