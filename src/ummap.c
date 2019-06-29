
#include "common.h"
#include "alloc_cache.h"
#include "futex.h"
#include "ummap_types.h"
#include "ummap_policy.h"
#include "ummap_util.h"
#include "ummap.h"

///////////////////////////////////
// PRIVATE DEFINITIONS & METHODS //
///////////////////////////////////

typedef struct sigaction saction_t;

#define MEM_FACTOR  0.9
#define PROT_FULL   (PROT_READ    | PROT_WRITE)
#define MMAP_FLAGS  (MAP_PRIVATE  | MAP_NORESERVE | MAP_ANONYMOUS)
#define MRMAP_FLAGS (MREMAP_FIXED | MREMAP_MAYMOVE)
#define FILE_FLAGS  (O_NOATIME    | O_DSYNC) // O_DIRECT
#define SIGEVICT    SIGRTMAX // Using SIGRTMAX to avoid conflicts
#define SHM_SEM_ID  "ummap_sem"
#define SHM_PID_ID  "ummap_pid"
#define SHM_RNK_ID  "ummap_rnk"
#define SHM_MEM_ID  "ummap_mem"
#define NUM_RANKS   (*g_status.num_ranks)
#define NUM_RANKS_C g_status.num_ranks_curr
#define MEM_SIZE    (*g_status.memsize)

#define IS_SEG_VALID(alloc_seg)    ((alloc_seg)->header & __UINT64_C(1))
#define IS_SEG_DIRTY(alloc_seg)    ((alloc_seg)->header & __UINT64_C(2))
#define IS_SEG_READFILE(alloc_seg) ((alloc_seg)->header & __UINT64_C(4))
#define GET_FLUSH_TIME(alloc_seg)  ((alloc_seg)->header >> 8)
#define SET_HEADER(alloc_seg, V, D, R, FT) \
    ((alloc_seg)->header = (uint64_t)(V | (D << 1) | (R << 2)) | (FT << 8))
#define RESET_VALID_FLAG(alloc_seg) ((alloc_seg)->header &= ~__UINT64_C(1))
#define GET_REG_ERR(context) ((ucontext_t *)context)->uc_mcontext.gregs[REG_ERR]
#define EINTR_SAFE(fn, result) while ((fn) != result && errno == EINTR);
#define SAFE_RELEASE(addr, fn) if (addr != NULL) { fn; addr = NULL; }
#define FREE(addr)         SAFE_RELEASE(addr, free(addr))
#define MUNMAP(addr, size) SAFE_RELEASE(addr, munmap(addr, size))
#define SEM_CLOSE(sem)     SAFE_RELEASE(sem,  sem_close(sem))
#define CALC_INDEX_S(ualloc, _alloc_seg) \
    ((uintptr_t)_alloc_seg - (uintptr_t)ualloc->alloc_seg) >> 5 // 32 bytes
#define SET_SHM_STRING(str, id, format, ...) \
    sprintf(str, "/%s_%d" format, id, getuid(),##__VA_ARGS__);
#define FUTEX_FN_DISABLE(futex_fn) \
    (g_status.ftxopt_enabled) ? futex_fn_empty : futex_fn;
#define CHECK_ALLOC(ualloc, ualloc_tmp, success_fn) \
    const uintptr_t base_addr = (uintptr_t)ualloc_tmp->addr; \
    const uintptr_t next_addr = base_addr + ualloc_tmp->size; \
    \
    if (addr >= base_addr && addr < next_addr) \
    { \
        success_fn \
        *ualloc = ualloc_tmp; \
        return ESUCCESS; \
    }

static ummap_status_t g_status        = { .r_index = UINT_MAX };
static iothread_t     g_iothread      = { 0 };
static futex_t        g_ualloc_futex  = FUTEX_INITIALIZER;
static sigset_t       g_sigevict_mask = { 0 };

// Create the cache for the allocations and also the list of recently-accessed,
// which guarantees efficient hot accesses compared to cold accesses
CREATE_CACHE(UAlloc, ummap_alloc_t*, g_ualloc, static);
CREATE_LIST(ualloc,  ummap_alloc_t,  g_ualloc, static);

// Methods are declared here to maintain the implementation order below
static int configure_mem_shm();
static int release_pf_handler();

// Empty handler for the futex functionality when handling page-faults
static int futex_fn_empty(futex_t *futex) { return ESUCCESS; }

static int getUAllocFromAddr(uintptr_t addr, ummap_alloc_t **ualloc)
{
    // Check if the address is inside the recently-accessed list
    for (ummap_alloc_t *ualloc_tmp = g_ualloc_list.front; ualloc_tmp != NULL;
         ualloc_tmp = ualloc_tmp->next)
    {
        CHECK_ALLOC(ualloc, ualloc_tmp,
        {
            // If the address is found, move the allocation to the front
            if (ualloc_tmp != g_ualloc_list.front)
            {
                pop_elem_ualloc(&g_ualloc_list,   ualloc_tmp);
                push_front_ualloc(&g_ualloc_list, ualloc_tmp);
            }
        });
    }
    
    // Alternatively, examine each allocation to look for the specific address
    for (int index_a = 0; index_a < g_ualloc_cache.count; index_a++)
    {
        CHECK_ALLOC(ualloc, g_ualloc_cache.data[index_a],
        {
            // If the address is found, add the allocation to the list
            push_front_ualloc(&g_ualloc_list, g_ualloc_cache.data[index_a]);
        });
    }
    
    // If we reach this point, the address is unknown
    return EINVAL;
}

static int writeSeg(ummap_alloc_t *ualloc, off_t index_s,
                    size_t size) __CHK_FN__
{
    const off_t offset_seg  = index_s << ualloc->seg_shift;
    const off_t offset_file = ualloc->offset + offset_seg;
    void        *addr_seg   = (void *)&ualloc->addr[offset_seg];
    
    // Set read-only permission to avoid further changes
    CHK(mprotect(addr_seg, size, PROT_READ));
    
    // Flush to storage with data integrity only
    CHKB((pwrite(ualloc->fd, addr_seg, size, offset_file) != size), EIO);
    
    // Increase the number of I/O writes
    g_status.num_writes++;
    
    return CHK_SUCCESS(CHK_EMPTY_ERROR_FN);
}

static void resetSeg(ummap_seg_t *alloc_seg, ummap_policy_t *policy)
{
    // Reset the properties of the segment and enable the read flag
    SET_HEADER(alloc_seg, TRUE, FALSE, TRUE, 0);
    
    // Notify the policy about the change from WRITE to READ, if needed
    if (contains_seg(&policy->list, alloc_seg))
    {
        policy->modify(&policy->list, alloc_seg, PAGEFAULT_READ);
    }
}

static int syncSeg(ummap_alloc_t *ualloc, ummap_seg_t *alloc_seg, off_t index_s,
                   uint8_t ignore_ts) __CHK_FN__
{
    const uint64_t flush_time = GET_FLUSH_TIME(alloc_seg);
    const uint64_t time_diff  = (ignore_ts) ? UINT64_MAX :
                                              (time(NULL) - flush_time);
    
    // Synchronize the segment if it is dirty and the conditions are met
    if (IS_SEG_DIRTY(alloc_seg) && time_diff >= ualloc->flush_interval)
    {
        // Acquire the lock for the segment
        CHK(futex_lock(&alloc_seg->futex));
        
        // Ensure that the segment has not been handled by another process
        if (flush_time == GET_FLUSH_TIME(alloc_seg))
        {
            DBGPRINT("Flushing segment 0x%zu (ignore_ts=%d time_diff=%zu)",
                          (index_s << ualloc->seg_shift), ignore_ts, time_diff);
            
            // Flush the segment to storage
            CHK(writeSeg(ualloc, index_s, ualloc->seg_size));
            
            // Reset the properties of the segment and notify the policy
            resetSeg(alloc_seg, ualloc->policy);
        }
        
        // Release the lock for the segment
        CHK(futex_unlock(&alloc_seg->futex));
    }
    
    return CHK_SUCCESS(CHK_EMPTY_ERROR_FN);
}

static int syncUAlloc(ummap_alloc_t *ualloc, uint8_t ignore_ts) __CHK_FN__
{
    const size_t num_seg = (ualloc->size >> ualloc->seg_shift);
    
    // Synchronize each segment of the allocation with storage, if dirty
    for (off_t index_s = 0; index_s < num_seg; index_s++)
    {
        ummap_seg_t *alloc_seg = &ualloc->alloc_seg[index_s];
        
        // Ensure that the segment is valid before trying to synchronize it
        if (IS_SEG_VALID(alloc_seg))
        {
            CHK(syncSeg(ualloc, alloc_seg, index_s, ignore_ts));
        }
    }
    
    CHK(fdatasync(ualloc->fd));
    
    return CHK_SUCCESS(CHK_EMPTY_ERROR_FN);
}

static int syncUAllocBulk(ummap_alloc_t *ualloc) __CHK_FN__
{
    const size_t num_seg = (ualloc->size >> ualloc->seg_shift);
    
    for (off_t index_s = 0, index_s_init = 0; index_s < num_seg; index_s++)
    {
        // Skip all the consecutive non-dirty segments
        while (!IS_SEG_DIRTY(&ualloc->alloc_seg[index_s]) &&
               ++index_s < num_seg);
        
        // Store the index of the first dirty segment found
        index_s_init = index_s;
        
        // Look for consecutive dirty segments and acquire their locks
        while (index_s < num_seg)
        {
            ummap_seg_t *alloc_seg = &ualloc->alloc_seg[index_s];
            
            if (!IS_SEG_DIRTY(alloc_seg)) break;
            
            CHK(futex_lock(&alloc_seg->futex));
        
            // Ensure that the segment is still dirty after acquiring the lock
            if (!IS_SEG_DIRTY(alloc_seg))
            {
                CHK(futex_unlock(&alloc_seg->futex));
                break;
            }
            
            index_s++;
        }
        
        if (index_s != index_s_init)
        {
            const size_t num_seg_seq  = (index_s - index_s_init);
            const size_t seg_size_seq = num_seg_seq * ualloc->seg_size;
            
            DBGPRINT("Flushing segments from 0x%zu (num_seg_seq=%zu)",
                              (index_s_init << ualloc->seg_shift), num_seg_seq);
            
            // Flush all the consecutive segments to storage
            CHK(writeSeg(ualloc, index_s_init, seg_size_seq));
        }
        
        // Update the metadata of the flushed segments and release their locks
        while (index_s_init < index_s)
        {
            ummap_seg_t *alloc_seg = &ualloc->alloc_seg[index_s_init++];
            
            // Reset the properties of the segment and notify the policy
            resetSeg(alloc_seg, ualloc->policy);
            
            CHK(futex_unlock(&alloc_seg->futex));
        }
    }
    
    CHK(fdatasync(ualloc->fd));
    
    return CHK_SUCCESS(CHK_EMPTY_ERROR_FN);
}

static int evictSeg(ssize_t req_size) __CHK_FN__
{
    for (ummap_alloc_t *ualloc = g_ualloc_list.back;
         req_size > 0 && ualloc != NULL;)
    {
        ummap_policy_t *policy    = ualloc->policy;
        ummap_seg_t    *alloc_seg = NULL;
        
        while (req_size > 0 &&
               (alloc_seg = policy->evict(&policy->list)) != NULL)
        {
            const off_t index_s    = CALC_INDEX_S(ualloc, alloc_seg);
            const off_t offset_seg = index_s << ualloc->seg_shift;
            void        *addr_seg  = (void *)&ualloc->addr[offset_seg];
            
            // Synchronize the segment with storage, if dirty
            CHK(syncSeg(ualloc, alloc_seg, index_s, TRUE));
            CHK(fdatasync(ualloc->fd));
            
            DBGPRINT("Removing local segment (index_s=%zu / req_size=%zu)\n",
                                                             index_s, req_size);
            
            // Remove the segment permissions and request the OS to release it
            CHK(mprotect(addr_seg, ualloc->seg_size, PROT_NONE));
            CHK(madvise(addr_seg,  ualloc->seg_size, MADV_DONTNEED));
            
            // Mark the segment as non-valid
            RESET_VALID_FLAG(alloc_seg);
            
            // Decrease the requested and estimated memory consumption
            req_size -= ualloc->seg_size;
            MEM_SIZE -= ualloc->seg_size;
        }
        
        // Advance the pointer for the next iteration
        ualloc = ualloc->prev;
        
        // Remove the current allocation from the pLRU, if needed
        if (is_empty_seg(&policy->list))
        {
            pop_back_ualloc(&g_ualloc_list);
        }
    }
    
    // Ensure that we have had enough segments (otherwise, an error ocurred)
    // CHKB((req_size > 0), ENOTRECOVERABLE); << Problem with multiple SIGEVICT!
    
    return CHK_SUCCESS(CHK_EMPTY_ERROR_FN);
}

static int notifyMemlimit(ssize_t req_size) __CHK_FN__
{
    sigval_t sigval = { .sival_ptr = NULL };
    
    // Check if only one process is available (i.e., an error ocurred)
    CHKB((NUM_RANKS == 1), EPERM);
    
    // Ensure that the structure that contains the memory consumption is set
    if (g_status.memsizes == NULL || NUM_RANKS_C != NUM_RANKS)
    {
        CHK(configure_mem_shm());
    }
    
    // Look for the PIDs with the highest memory consumption
    for (uint32_t m_index = (g_status.r_index + 1) % NUM_RANKS_C;
         m_index != g_status.r_index; m_index = (m_index + 1) % NUM_RANKS_C)
    {
        const size_t mem_size = *g_status.memsizes[m_index];
        
        if (mem_size > g_status.memlimit_rank)
        {
            const int32_t pid = g_status.ranks[m_index];
            
            DBGPRINT("Notifying process %d (ru=%zu)", pid, mem_size);
            
            CHK(sigqueue(pid, SIGEVICT, sigval));
        }
    }
    
    return CHK_SUCCESS(CHK_EMPTY_ERROR_FN);
}

static int ensureSegFit(size_t seg_size) __CHK_FN__
{
    uint8_t evict_seg  = ((MEM_SIZE + seg_size) > g_status.memlimit_rank);
    uint8_t notify_mem = FALSE;
    
    // Dynamic memory allocations require considering the current used memory
    if (g_status.mconfig == UMMAP_MEMCONFIG_DYNAMIC)
    {
        size_t usedram = 0;
        CHK(get_usedram(&usedram));
        
        notify_mem = (usedram + seg_size) > g_status.memlimit;
        evict_seg  = (evict_seg && notify_mem);
    }
    
    // Evict a local segment if the current process exceeds its limit
    if (evict_seg)
    {
        DBGPRINT("Evicting a local segment (ru=%zu / rlimit=%zu)\n",
                                              MEM_SIZE, g_status.memlimit_rank);
        
        CHK(evictSeg(seg_size));
    }
    // Alternatively, notify the processes that are exceeding their limit
    else if (notify_mem)
    {
        DBGPRINT("Notifying another process (ru=%zu / rlimit=%zu)",
                                              MEM_SIZE, g_status.memlimit_rank);
        
        CHK(notifyMemlimit(g_status.memlimit_rank - MEM_SIZE));
    }
    
    return CHK_SUCCESS(CHK_EMPTY_ERROR_FN);
}

static void* iothread_handler(void *arg) __CHK_FN__
{
    int        hr       = ESUCCESS;
    timespec_t ts       = { 0 };
    sigset_t   sig_mask = { 0 };
    
    // Ensure that no signals are delivered to the I/O thread
    CHKEXIT(sigemptyset(&sig_mask));
    CHKEXIT(sigaddset(&sig_mask, SIGSEGV));
    CHKEXIT(sigaddset(&sig_mask, SIGEVICT));
    CHKEXIT(sigprocmask(SIG_BLOCK, &sig_mask, NULL));
    
    while (g_iothread.is_active)
    {
        // Force the thread to wait for the minimum flush interval
        CHKEXIT(ts_set(&ts, g_iothread.min_flush_interval, 0));
        EINTR_SAFE((hr = sem_timedwait(&g_iothread.sem, &ts)), ESUCCESS);
        
        // Check if an unexpected error has been found
        CHKBEXIT((hr && errno != ETIMEDOUT), ENOLCK);
        
        // Set the futex operations to avoid issues handling the segments
        g_iothread.futex_lock   = futex_lock;
        g_iothread.futex_unlock = futex_unlock;
        
        // Acquire the lock for the allocation cache
        CHKEXIT(futex_lock(&g_ualloc_futex));
        
        // Examine each allocation to perform a synchronization with storage
        for (int index_a = 0; index_a < g_ualloc_cache.count; index_a++)
        {
            CHKEXIT(syncUAlloc(g_ualloc_cache.data[index_a], FALSE));
        }
        
        // Release the lock for the allocation cache
        CHKEXIT(futex_unlock(&g_ualloc_futex));
        
        // Reset the futex operations to reduce the overhead while inactive
        g_iothread.futex_lock   = FUTEX_FN_DISABLE(futex_lock);
        g_iothread.futex_unlock = FUTEX_FN_DISABLE(futex_unlock);
    }
    
    return CHK_VALUE(NULL, CHK_EMPTY_ERROR_FN);
}

static void sigsegv_handler(int sig, siginfo_t *si, void *context) __CHK_FN__
{
    const uintptr_t addr_si     = (uintptr_t)si->si_addr;
    const pf_type_t pf_type     = (pf_type_t)((GET_REG_ERR(context) & 2) >> 1);
    const uint8_t   is_pf_write = (pf_type == PAGEFAULT_WRITE);
    ummap_alloc_t   *ualloc     = NULL;
    off_t           index_s     = 0;
    off_t           offset_seg  = 0;
    ummap_seg_t     *alloc_seg  = NULL;
    void            *addr_seg   = NULL;
    ummap_policy_t  *policy     = NULL;
    
    // DBGPRINT("SIGSEGV captured for address 0x%zu", addr_si);
    
    // Retrieve the allocation and exit if the address is unknown (i.e., the
    // SIGSEGV corresponds to another address or unrelated error) or if the
    // operation is not allowed (i.e., writing on a read-only buffer)
    CHKEXIT(getUAllocFromAddr(addr_si, &ualloc));
    CHKBEXIT((is_pf_write && !(ualloc->prot & PROT_WRITE)), EPERM);
    
    // Retrieve the specific segment associated with the faulting address
    index_s    = (addr_si - (uintptr_t)ualloc->addr) >> ualloc->seg_shift;
    offset_seg = (index_s << ualloc->seg_shift);
    alloc_seg  = &ualloc->alloc_seg[index_s];
    addr_seg   = (void *)&ualloc->addr[offset_seg];
    policy     = ualloc->policy;
    
    // DBGPRINT("Segment 0x%zu found (index_s=%zu)", offset_seg, index_s);
    
    if (!IS_SEG_VALID(alloc_seg))
    {
        // Calculate the main memory limit allowed per rank
        if (g_status.memlimit_rank == 0)
        {
            // <<<<<< Important: Can cause problems if not all ranks are active!
            g_status.memlimit_rank = g_status.memlimit / (size_t)NUM_RANKS;
        }
        
        // Ensure that we can fit another segment
        CHKEXIT(ensureSegFit(ualloc->seg_size));
        
        // Check if the segment must be read from storage
        if (IS_SEG_READFILE(alloc_seg))
        {
            const off_t offset_file = ualloc->offset + offset_seg;
            
            DBGPRINT("Reading segment from storage (offset=%zu)", offset_file);
            
            // Temporarily set permissions and read the segment from storage
            CHKEXIT(mprotect(addr_seg, ualloc->seg_size, PROT_FULL));
            CHKBEXIT((pread(ualloc->fd, addr_seg, ualloc->seg_size,
                            offset_file) != ualloc->seg_size), EIO);
            
            // Increase the number of I/O reads
            g_status.num_reads++;
        }
    
        // Increase the estimated memory consumption
        MEM_SIZE += ualloc->seg_size;
    }
    
    // Acquire the lock for the segment
    CHKEXIT(g_iothread.futex_lock(&alloc_seg->futex));
    
    // DBGPRINT("Marking segment corresponding to a %s fault",
    //                                        (is_pf_write) ? "WRITE" : "READ");
    
    // Update the protection of the segment accordingly
    CHKEXIT(mprotect(addr_seg, ualloc->seg_size,
                     (PROT_READ | (is_pf_write * PROT_WRITE))));
    
    // Update the header to set the timestamp and the dirty flag, if needed
    SET_HEADER(alloc_seg, TRUE, is_pf_write, !!IS_SEG_READFILE(alloc_seg),
               (is_pf_write * time(NULL)));
    
    // Notify the policy about the captured page fault
    policy->notify(&policy->list, alloc_seg, pf_type);
    
    // Release the lock for the segment
    CHKEXIT(g_iothread.futex_unlock(&alloc_seg->futex));
    
    // DBGPRINT("SIGSEGV for address 0x%zu handled correctly!", addr_si);
    
    return CHK_VOID(CHK_EMPTY_ERROR_FN);
}

static void sigevict_handler(int sig, siginfo_t *si, void *context) __CHK_FN__
{
    const ssize_t diff = (MEM_SIZE - g_status.memlimit_rank);
    
    DBGPRINT("SIGEVICT captured (diff=%zu memsize=%zu)", diff, MEM_SIZE);
    
    // Ensure that we are still exceeding the limit per rank (otherwise, ignore
    // the request to avoid issues)
    if (diff > 0)
    {
        CHKEXIT(evictSeg(diff >> 1));
    }
    
    DBGPRINT("SIGEVICT handled correctly! (memsize=%zu)", MEM_SIZE);
    
    return CHK_VOID(CHK_EMPTY_ERROR_FN);
}

static int configure_pf_handler() __CHK_FN__
{
    saction_t sa            = { .sa_flags = SA_SIGINFO }; // SA_RESTART
    double    factor        = MEM_FACTOR;
    char      str[NAME_MAX] = { 0 };
    
    // Ensure that we do not initialize twice the library (i.e., not supported)
    CHKB((g_status.r_index != UINT_MAX), ENOTSUP);
    
    // Retrieve the global settings from the ENV variables
    {
        CHK(get_env("UMMAP_MEMCONFIG", "%s", (void *)str));
        g_status.mconfig = (mconfig_t)!strcmp(str, "dynamic");
        
        str[0] = '\0'; // Reset the string
        CHK(get_env("UMMAP_BULK_SYNC", "%s", (void *)str));
        g_status.bsync_enabled = (strcmp(str, "false") != 0);
        
        str[0] = '\0'; // Reset the string
        CHK(get_env("UMMAP_FUTEX_OPT", "%s", (void *)str));
        g_status.ftxopt_enabled = (strcmp(str, "false") != 0);
        
        // Retrieve the main memory limit for all the allocations
        CHK(get_env("UMMAP_MEM_LIMIT", "%zu", (void *)&g_status.memlimit));
        
        // If no limit was provided, calculate it with the "factor"
        if (g_status.memlimit == 0)
        {
            CHK(get_env("UMMAP_MEM_FACTOR", "%lf", (void *)&factor));
            CHK(get_totalram(&g_status.memlimit));
            
            g_status.memlimit = (double)g_status.memlimit * factor;
        }
    }
    
    // Define the shared memory structures for out-of-core support
    {
        // Open the shared synchronization semaphore
        SET_SHM_STRING(str, SHM_SEM_ID, "");
        CHK(open_sem(str, 1, &g_status.sem));
        
        // Acquire the shared synchronization semaphore
        CHK(sem_wait(g_status.sem));
        
        // Open the shared memory segment for the rank IDs
        SET_SHM_STRING(str, SHM_PID_ID, "");
        CHK(open_shm(str, sizeof(int32_t), TRUE, (void **)&g_status.ranks));
        
        // Open the shared memory segment for the number of ranks
        SET_SHM_STRING(str, SHM_RNK_ID, "");
        CHK(open_shm(str, sizeof(uint32_t), FALSE,
                     (void **)&g_status.num_ranks));
        
        // Update the rank index, the number of ranks and store the PID
        g_status.r_index                 = NUM_RANKS;
        g_status.num_ranks_curr          = ++NUM_RANKS;
        g_status.ranks[g_status.r_index] = getpid();
        
        // Release the shared synchronization semaphore
        CHK(sem_post(g_status.sem));
        
        // Open the shared memory segment to store the memory consumption
        SET_SHM_STRING(str, SHM_MEM_ID, "_%d", getpid());
        CHK(open_shm(str, sizeof(uint64_t), FALSE, (void **)&g_status.memsize));
    }
    
    // Set-up and launch the I/O thread
    {
        g_iothread.is_active          = TRUE;
        g_iothread.min_flush_interval = UINT_MAX;
        g_iothread.futex_lock         = FUTEX_FN_DISABLE(futex_lock);
        g_iothread.futex_unlock       = FUTEX_FN_DISABLE(futex_unlock);
        CHK(sem_init(&g_iothread.sem, 0, 0));
        CHK(pthread_create(&g_iothread.tid, NULL, iothread_handler, NULL));
    }
    
    // Capture the SIGSEGV / SIGEVICT events
    {
        // Block other signals to avoid interrupting the handlers
        CHK(sigfillset(&sa.sa_mask));
        
        sa.sa_sigaction = sigsegv_handler;
        CHK(sigaction(SIGSEGV, &sa, NULL));
        
        sa.sa_sigaction = sigevict_handler;
        CHK(sigaction(SIGEVICT, &sa, NULL));
    
        // Initialize the signal set to prevent SIGEVICT while synchronizing
        sigemptyset(&g_sigevict_mask);
        sigaddset(&g_sigevict_mask, SIGEVICT);
    }
    
    // Reset the I/O stats
    {
        g_status.num_reads  = 0;
        g_status.num_writes = 0;
    }
    
    return CHK_SUCCESS({
                           // If an error is encountered, release everything
                           release_pf_handler();
                       });
}

static int configure_mem_shm() __CHK_FN__
{
    const uint32_t num_ranks     = NUM_RANKS; // Store it to avoid issues
    const off_t    m_init        = (g_status.memsizes) ? NUM_RANKS_C : 0;
    const size_t   size          = sizeof(uint64_t *) * num_ranks;
    char           str[NAME_MAX] = { 0 };
    
    g_status.memsizes = (uint64_t **)realloc(g_status.memsizes, size);
    
    // Remap the shared memory structure that contains the PIDs, if needed
    if (NUM_RANKS_C != num_ranks)
    {
        MUNMAP(g_status.ranks, NUM_RANKS_C * sizeof(int32_t));
        SET_SHM_STRING(str, SHM_PID_ID, "");
        CHK(open_shm(str, 0, FALSE, (void **)&g_status.ranks));
        
        // Update the number of ranks accordingly
        NUM_RANKS_C = num_ranks;
    }
    
    // Map the memory consumption of the other processes (intra-node)
    for (uint32_t m_index = m_init; m_index < num_ranks; m_index++)
    {
        SET_SHM_STRING(str, SHM_MEM_ID, "_%d", g_status.ranks[m_index]);
        CHK(open_shm(str, 0, FALSE, (void **)&g_status.memsizes[m_index]));
    }
    
    return CHK_SUCCESS(CHK_EMPTY_ERROR_FN);
}

static int release_pf_handler() __CHK_FN__
{
    saction_t sa            = { .sa_handler = SIG_DFL };
    char      str[NAME_MAX] = { 0 };
    
    // Wait for the I/O thread to finish and release it
    if (g_iothread.is_active) // Note: This is needed for error handling only!
    {
        g_iothread.is_active = FALSE;
        CHK(sem_post(&g_iothread.sem));
        CHK(pthread_join(g_iothread.tid, NULL));
        CHK(sem_destroy(&g_iothread.sem));
    }
    
    // Ignore the SIGSEGV / SIGEVICT events
    {
        CHK(sigaction(SIGSEGV,  &sa, NULL));
        CHK(sigaction(SIGEVICT, &sa, NULL));
    }
    
    // Clean all the existing shared memory segments
    {
        MUNMAP(g_status.memsize, sizeof(uint64_t));
        SET_SHM_STRING(str, SHM_MEM_ID, "_%d", getpid());
        CHKB((shm_unlink(str) && errno != ENOENT), errno);
        
        if (g_status.memsizes != NULL)
        {
            for (uint32_t m_index = 0; m_index < NUM_RANKS_C; m_index++)
            {
                MUNMAP(g_status.memsizes[m_index], sizeof(uint64_t));
            }
            
            FREE(g_status.memsizes);
        }
        
        // Mark the rank as non-valid to avoid conflicts with other processes
        if (g_status.ranks != NULL)
        {
            // Acquire the shared synchronization semaphore
            // CHK(sem_wait(g_status.sem));
            
            // NUM_RANKS--; << Avoiding to change the global number of ranks!
            g_status.ranks[g_status.r_index] = INT_MAX;
            
            // Release the shared synchronization semaphore
            // CHK(sem_post(g_status.sem));
        }

        MUNMAP(g_status.ranks, NUM_RANKS_C * sizeof(int32_t));
        SET_SHM_STRING(str, SHM_PID_ID, "");
        CHKB((shm_unlink(str) && errno != ENOENT), errno);
        
        MUNMAP(g_status.num_ranks, sizeof(uint32_t));
        SET_SHM_STRING(str, SHM_RNK_ID, "");
        CHKB((shm_unlink(str) && errno != ENOENT), errno);

        SEM_CLOSE(g_status.sem);
        SET_SHM_STRING(str, SHM_SEM_ID, "");
        CHKB((sem_unlink(str) && errno != ENOENT), errno);
    }
    
    return CHK_SUCCESS(CHK_EMPTY_ERROR_FN);
}

static void __attribute__ ((constructor)) ummap_startup()
{
    // Use the release function to clean-up existing shared files, if any
    release_pf_handler();
    
    DBGPRINT("uMMAP-IO startup configuration executed correctly.");
}


//////////////////////////////////
// PUBLIC DEFINITIONS & METHODS //
//////////////////////////////////

int ummap(size_t size, size_t seg_size, int prot, int fd, off_t offset,
          unsigned int flush_interval, int read_file, int ptype,
          void **ptr) __CHK_FN__
{
    const size_t  num_seg = size / seg_size;
    const int     flags   = fcntl(fd, F_GETFL);
    ummap_alloc_t *ualloc = NULL;
    char          *addr   = NULL;
    
    // Make sure that the segment size is correctly set
    CHKB(((size % seg_size) || (seg_size < sysconf(_SC_PAGESIZE)) ||
          (seg_size & ~(seg_size - 1)) != seg_size ), EINVAL); // Power of 2
    
    // Duplicate the file descriptor and ensure that it is properly configured
    fd = dup(fd);
    CHK(fcntl(fd, F_SETFL, (flags | FILE_FLAGS)));
    
    // Create an anonymous mapping to reserve the virtual addresses
    addr = (char *)mmap(NULL, size, PROT_NONE, MMAP_FLAGS, -1, 0);
    CHKB((addr == MAP_FAILED), ENOMEM);
    
    // Prepare the allocation to be stored inside the cache
    ualloc = (ummap_alloc_t *)calloc(1, sizeof(ummap_alloc_t));
    ualloc->addr           = addr;
    ualloc->size           = size;
    ualloc->seg_size       = seg_size;
    ualloc->seg_shift      = log2s(seg_size);
    ualloc->fd             = fd;
    ualloc->offset         = offset;
    ualloc->prot           = prot;
    ualloc->flush_interval = flush_interval + !flush_interval; // Force ">=1"
    
    // Allocate and reset the memory segment structure
    ualloc->alloc_seg = (ummap_seg_t *)calloc(num_seg, sizeof(ummap_seg_t));
    
    for (off_t index_s = 0; index_s < num_seg; index_s++)
    {
        ummap_seg_t *alloc_seg = &ualloc->alloc_seg[index_s];
        
        SET_HEADER(alloc_seg, FALSE, FALSE, !!read_file, 0);
        alloc_seg->futex = (futex_t)FUTEX_INITIALIZER;
    }
    
    // Create the evict policy based on the given type
    CHK(umpolicy_create((ummap_ptype_t)ptype, &ualloc->policy));
    
    // Ensure that the page-fault mechanism is configured
    if (!g_iothread.is_active)
    {
        CHK(configure_pf_handler());
    }
    
    // Add the allocation to the cache
    CHK(futex_lock(&g_ualloc_futex));
    CHK(addUAlloc(ualloc));
    CHK(futex_unlock(&g_ualloc_futex));
    
    // Update the flush interval and notify the I/O thread, if needed
    if (ualloc->flush_interval < g_iothread.min_flush_interval)
    {
        g_iothread.min_flush_interval = ualloc->flush_interval;
        CHK(sem_post(&g_iothread.sem));
    }
    
    // Return the pointer
    *ptr = addr;
    
    return CHK_SUCCESS({
                           // If an error is encountered, release everything
                           MUNMAP(addr, size);
                           if (ualloc) FREE(ualloc->alloc_seg);
                           FREE(ualloc);
                       });
}

int umsync(void *addr, int evict) __CHK_FN__
{
    ummap_alloc_t *ualloc = NULL;
    
    // Retrieve the allocation and ensure that the addresses match
    CHK(getUAllocFromAddr((uintptr_t)addr, &ualloc));
    CHKB((addr != ualloc->addr), EINVAL);
    
    // Block the SIGEVICT signal to avoid issues (e.g., the segment that is
    // evicted could be handled here, which can cause undefined behaviour)
    CHK(sigprocmask(SIG_BLOCK, &g_sigevict_mask, NULL));
    
    // Sinchronize all the segments with storage
    if (g_status.bsync_enabled)
    {
        CHK(syncUAllocBulk(ualloc));
    }
    else
    {
        CHK(syncUAlloc(ualloc, TRUE));
    }
    
    // If requested, release and reset the valid flag of all the segments
    if (evict)
    {
        ummap_policy_t *policy    = ualloc->policy;
        ummap_seg_t    *alloc_seg = NULL;
        
        while ((alloc_seg = policy->evict(&policy->list)) != NULL)
        {
            RESET_VALID_FLAG(alloc_seg);
            
            // Decrease the estimated memory consumption
            MEM_SIZE -= ualloc->seg_size;
        }
        
        // Remove the allocation from the recently-accessed list
        if (contains_ualloc(&g_ualloc_list, ualloc))
        {
            pop_elem_ualloc(&g_ualloc_list, ualloc);
        }
        
        CHK(mprotect(ualloc->addr, ualloc->size, PROT_NONE));
        CHK(madvise(ualloc->addr,  ualloc->size, MADV_DONTNEED));
    }
    
    // Unblock the SIGEVICT signal
    CHK(sigprocmask(SIG_UNBLOCK, &g_sigevict_mask, NULL));
    
    return CHK_SUCCESS(CHK_EMPTY_ERROR_FN);
}

int umremap(void *old_addr, int fd, off_t offset, int sync,
            void **new_addr) __CHK_FN__
{
    ummap_alloc_t *ualloc = NULL;
    
    // Retrieve the allocation and ensure that the addresses match
    CHK(getUAllocFromAddr((uintptr_t)old_addr, &ualloc));
    CHKB((old_addr != ualloc->addr), EINVAL);
    
    // Block the SIGEVICT signal to avoid issues
    CHK(sigprocmask(SIG_BLOCK, &g_sigevict_mask, NULL));
    
    // Sinchronize all the segments with storage, if needed
    if (sync)
    {
        CHK(syncUAllocBulk(ualloc));
    }
    
    // Remap the original address space, if requested 
    if (old_addr != *new_addr)
    {
        // Create an anonymous mapping to reserve the new virtual addresses
        if (*new_addr == NULL)
        {
            *new_addr = (char *)mmap(NULL, ualloc->size, PROT_NONE, MMAP_FLAGS,
                                     -1, 0);
            CHKB((*new_addr == MAP_FAILED), ENOMEM);
        }
        
        ualloc->addr = mremap(old_addr, ualloc->size, ualloc->size, MRMAP_FLAGS,
                              *new_addr);
        CHKB((ualloc->addr == MAP_FAILED), EACCES);
    }
    
    if (fd >= 0)
    {
        const int flags = fcntl(fd, F_GETFL);
        
        // Close the previous file descriptor
        CHK(close(ualloc->fd));
        
        // Duplicate and correctly configure the new file descriptor
        ualloc->fd = dup(fd);
        CHK(fcntl(ualloc->fd, F_SETFL, (flags | FILE_FLAGS)));
    }
    
    ualloc->offset = (offset != OFF_T_MAX) ? offset : ualloc->offset;
    
    // Unblock the SIGEVICT signal
    CHK(sigprocmask(SIG_UNBLOCK, &g_sigevict_mask, NULL));
    
    return CHK_SUCCESS(CHK_EMPTY_ERROR_FN);
}

int umunmap(void *addr, int sync) __CHK_FN__
{
    ummap_alloc_t  *ualloc    = NULL;
    ummap_policy_t *policy    = NULL;
    ummap_seg_t    *alloc_seg = NULL;
    
    // Retrieve the allocation and ensure that the addresses match
    CHK(getUAllocFromAddr((uintptr_t)addr, &ualloc));
    CHKB((addr != ualloc->addr), EINVAL);
    
    // Remove the allocation from the cache
    CHK(futex_lock(&g_ualloc_futex));
    CHK(removeUAlloc(ualloc));
    CHK(futex_unlock(&g_ualloc_futex));
    
    // Remove the allocation from the recently-accessed list
    if (contains_ualloc(&g_ualloc_list, ualloc))
    {
        pop_elem_ualloc(&g_ualloc_list, ualloc);
    }
    
    // Sinchronize all the segments with storage, if needed
    if (sync)
    {
        CHK(syncUAllocBulk(ualloc));
    }
    
    // Release the mapped addresses and close the file descriptor
    CHK(munmap((void *)ualloc->addr, ualloc->size));
    CHK(close(ualloc->fd));
    
    // Release all the internal allocations
    policy = ualloc->policy;
    while ((alloc_seg = policy->evict(&policy->list)) != NULL)
    {
        // Decrease the estimated memory consumption
        MEM_SIZE -= ualloc->seg_size;
    }
    
    umpolicy_release(policy);
    free(ualloc->alloc_seg);
    free(ualloc);
    
    // If this is the last allocation, release the page-fault mechanism
    if (g_ualloc_cache.count == 0)
    {
        CHK(release_pf_handler());
    }
    
    return CHK_SUCCESS(CHK_EMPTY_ERROR_FN);
}

int umstats(unsigned int *num_reads, unsigned int *num_writes)
{
    *num_reads  = g_status.num_reads;
    *num_writes = g_status.num_writes;
    
    return ESUCCESS;
}

