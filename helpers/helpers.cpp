#pragma once

#include <mast1c0re.hpp>

#pragma region Frequent functions

typedef uint64_t ptr64_t; // void *

void printf_debug(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    char debug_message[8192] = {0};
    PS2::vsprintf(debug_message, format, args);
    va_end(args);
    PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_MDBG_SERVICE),
        7,
        PVAR_TO_NATIVE(debug_message),
        0
    );
    PS::Debug.printf(debug_message);
}

int64_t reset_errno()
{
    int64_t reset = 0;
    PS::memcpy(PS::__error(), PVAR_TO_NATIVE(&reset), sizeof(reset));
    return reset;
}

int64_t read_errno()
{
    return DEREF(PS::__error());
}

#pragma endregion

#pragma region Syscall wrappers

ptr64_t syscall_wrappers[0x300] = {0};

bool buf_match(const uint8_t* buf, const uint8_t* pattern, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++)
        if (buf[i] != pattern[i]) return false;
    return true;
}

// "48 c7 c0 ? ? ? ? 49 89 ca 0f 05" (12 bytes)
void syscall_init()
{
    ptr64_t libkernel_base = LIBKERNEL(0); // libkernel base
    uint32_t size = 0x40000; // libkernel .text size
    printf_debug("syscall_init: libkernel_base %p\n", libkernel_base);

    uint8_t* buffer = (uint8_t*)PS2::malloc(size);
    if (!buffer) {
        printf_debug("syscall_init(): failed to allocate buffer\n");
        return;
    }
    PS::memcpy(PVAR_TO_NATIVE(buffer), libkernel_base, size);

    printf_debug("syscall_init(): scanning libkernel at %p\n", buffer);
    for (uint32_t i = 0; i < size - 11; i++) {
        if (!buf_match(buffer + i, (uint8_t*)"\x48\xC7\xC0", 3)) continue;
        if (!buf_match(buffer + i + 3 + 4, (uint8_t*)"\x49\x89\xCA\x0F\x05", 5)) continue;
        syscall_wrappers[*(uint32_t*)(buffer + i + 3)] = libkernel_base + i;
        i += 11;
    }
    PS2::free((void*)buffer);
    printf_debug("syscall_init(): DONE! ;3\n");
}

#pragma endregion

#pragma region Kernel functions

// sys/cpuset.h
#define CPU_LEVEL_WHICH 3
#define CPU_WHICH_TID   1

int32_t get_affinity(uint64_t *mask)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_CPUSET_GETAFFINITY),
        CPU_LEVEL_WHICH,
        CPU_WHICH_TID,
        -1,
        8,
        PVAR_TO_NATIVE(mask)
    );
    if (ret != 0) printf_debug("get_affinity returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

int32_t set_affinity(uint64_t *mask)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_CPUSET_SETAFFINITY),
        CPU_LEVEL_WHICH,
        CPU_WHICH_TID,
        -1,
        8,
        PVAR_TO_NATIVE(mask)
    );
    if (ret != 0) printf_debug("set_affinity returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

// sys/rtprio.h
#define RTP_LOOKUP 0
#define RTP_SET 1
#define RTP_PRIO_REALTIME 2
#define RTP_PRIO_NORMAL	3
#define RTP_PRIO_IDLE 4

struct rtprio_s
{
    uint16_t type;
    uint16_t prio;
};

int32_t set_priority(rtprio_s *rtprio)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_RTPRIO_THREAD),
        RTP_SET,
        0,
        PVAR_TO_NATIVE(rtprio)
    );
    if (ret != 0) printf_debug("set_priority returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

int32_t get_priority(rtprio_s *rtprio)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_RTPRIO_THREAD),
        RTP_LOOKUP,
        0,
        PVAR_TO_NATIVE(rtprio)
    );
    if (ret != 0) printf_debug("get_priority returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

// sys/socket.h
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6_ 28
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOL_SOCKET 0xffff
#define IPPROTO_UDP 17
#define IPPROTO_TCP 6

struct unixpair_s
{
    uint32_t block_fd;
    uint32_t unblock_fd;
};

int32_t create_unixpair(unixpair_s *unixpair)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_SOCKETPAIR),
        AF_UNIX,
        SOCK_STREAM,
        0, // protocol
        PVAR_TO_NATIVE(unixpair)
    );
    if (ret != 0) printf_debug("create_unixpair returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

int32_t create_ipv6udp()
{
    int32_t sd = PS::socket(AF_INET6_, SOCK_DGRAM, IPPROTO_UDP);
    if (sd < 0) printf_debug("create_ipv6udp returned: %d errno: %p\n", sd, read_errno());
    return sd;
}

// netinet6/in6.h
#define IPV6_RTHDR 51

int32_t get_rthdr(int32_t sd, void *val, socklen_t *len)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL__GETSOCKOPT),
        sd,
        IPPROTO_IPV6,
        IPV6_RTHDR,
        PVAR_TO_NATIVE(val),
        PVAR_TO_NATIVE(len)
    );
    if (ret != 0) printf_debug("get_rthdr returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

int32_t set_rthdr(int32_t sd, void *val, socklen_t len)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_SETSOCKOPT),
        sd,
        IPPROTO_IPV6,
        IPV6_RTHDR,
        PVAR_TO_NATIVE(val),
        len
    );
    if (ret != 0) printf_debug("set_rthdr returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

int32_t free_rthdrs(int32_t *sds, uint32_t num_sds)
{
    int32_t ret = 0;
    for (uint32_t i = 0; i < num_sds; i++)
    {
        if (sds[i] < 0) continue;
        int32_t _ret = set_rthdr(sds[i], 0, 0);
        ret = _ret || ret;
    }
    if (ret != 0) printf_debug("free_rthdrs returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

#pragma endregion

#pragma region ScePthread functions

typedef ptr64_t ScePthread;
typedef ptr64_t ScePthreadAttr;

int32_t scePthreadCreate(
    ScePthread *thread,
    const ScePthreadAttr *attr,
    ptr64_t entry, // void *(*entry)(void *)
    void *arg,
    const char *name
)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_SCE_PTHREAD_CREATE),
        PVAR_TO_NATIVE(thread),
        PVAR_TO_NATIVE(attr),
        entry,
        PVAR_TO_NATIVE(arg),
        PVAR_TO_NATIVE(name)
    );
    if (ret != 0) printf_debug("scePthreadCreate returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

int32_t scePthreadJoin(
    ScePthread thread,
    ptr64_t *value_ptr // void **value_ptr
)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_SCE_PTHREAD_JOIN),
        thread,
        PVAR_TO_NATIVE(value_ptr)
    );
    if (ret != 0) printf_debug("scePthreadJoin returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

int32_t scePthreadAttrInit(
    ScePthreadAttr *attr
)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_SCE_PTHREAD_ATTR_INIT),
        PVAR_TO_NATIVE(attr)
    );
    if (ret != 0) printf_debug("scePthreadAttrInit returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

int32_t scePthreadAttrSetstack(
    ScePthreadAttr *attr,
    void *stackAddr,
    size_t stackSize
)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_SCE_PTHREAD_ATTR_SETSTACK),
        PVAR_TO_NATIVE(attr),
        PVAR_TO_NATIVE(stackAddr),
        stackSize
    );
    if (ret != 0) printf_debug("scePthreadAttrSetstack returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

int32_t scePthreadAttrDestroy(
    ScePthreadAttr *attr
)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_SCE_PTHREAD_ATTR_DESTROY),
        PVAR_TO_NATIVE(attr)
    );
    if (ret != 0) printf_debug("scePthreadAttrDestroy returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

typedef ptr64_t ScePthreadBarrier;
typedef ptr64_t ScePthreadBarrierattr;

int32_t scePthreadBarrierInit(
    ScePthreadBarrier *barrier,
    const ScePthreadBarrierattr *attr,
    uint32_t count,
    const char *name
)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_SCE_PTHREAD_BARRIER_INIT),
        PVAR_TO_NATIVE(barrier),
        PVAR_TO_NATIVE(attr),
        count,
        PVAR_TO_NATIVE(name)
    );
    if (ret != 0) printf_debug("scePthreadBarrierInit returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

int32_t scePthreadBarrierDestroy(ScePthreadBarrier *barrier)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_SCE_PTHREAD_BARRIER_DESTROY),
        PVAR_TO_NATIVE(barrier)
    );
    if (ret != 0) printf_debug("scePthreadBarrierDestroy returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

#pragma endregion

#pragma region SceAIO functions

// SceAIO submit commands
#define SCE_KERNEL_AIO_CMD_READ     0x001
#define SCE_KERNEL_AIO_CMD_WRITE    0x002
#define SCE_KERNEL_AIO_CMD_MASK     0xfff
// SceAIO submit command flags
#define SCE_KERNEL_AIO_CMD_MULTI    0x1000
// SceAIO submit command priorities
#define SCE_KERNEL_AIO_PRIORITY_LOW     1
#define SCE_KERNEL_AIO_PRIORITY_MID     2
#define SCE_KERNEL_AIO_PRIORITY_HIGH    3

typedef struct SceKernelAioResult {
    int64_t returnValue;
    uint32_t state;
} SceKernelAioResult;

typedef struct {
    off_t offset;
    size_t nbyte;
    ptr64_t buf; // void *buf;
    ptr64_t result; // SceKernelAioResult *result;
    int32_t fd;
    uint8_t _pad[4];
} SceKernelAioRWRequest;

typedef int32_t SceKernelAioSubmitId;
typedef int32_t SceKernelAioError;

// Max number of requests that can be created/polled/canceled/deleted/waited
#define MAX_REQS 0x80
// Dummy buffer to hold errors during AIO operations
SceKernelAioError aio_errs[MAX_REQS] = {0};

int32_t aio_submit_cmd(
    uint32_t cmd,
    SceKernelAioRWRequest reqs[],
    uint32_t num_reqs,
    uint32_t prio,
    SceKernelAioSubmitId ids[]
)
{
    // ptr64_t addr = 0;
    // if (cmd == SCE_KERNEL_AIO_CMD_READ)
    //     addr = LIB_KERNEL_SCE_KERNEL_AIO_SUBMIT_READ_COMMANDS;
    // else if (cmd == SCE_KERNEL_AIO_CMD_WRITE)
    //     addr = LIB_KERNEL_SCE_KERNEL_AIO_SUBMIT_WRITE_COMMANDS;
    // else if (cmd == SCE_KERNEL_AIO_CMD_READ | SCE_KERNEL_AIO_CMD_MULTI)
    //     addr = LIB_KERNEL_SCE_KERNEL_AIO_SUBMIT_READ_COMMANDS_MULTIPLE;
    // else if (cmd == SCE_KERNEL_AIO_CMD_WRITE | SCE_KERNEL_AIO_CMD_MULTI)
    //     addr = LIB_KERNEL_SCE_KERNEL_AIO_SUBMIT_WRITE_COMMANDS_MULTIPLE;
    // else
    // {
    //     printf_debug("aio_submit_cmd: Invalid command %x\n", cmd);
    //     return -1;
    // }

    int32_t ret = PS::Breakout::call(
        // LIBKERNEL(addr),
        syscall_wrappers[SYS_AIO_SUBMIT_CMD],
        cmd,
        PVAR_TO_NATIVE(reqs),
        num_reqs,
        prio,
        PVAR_TO_NATIVE(ids)
    );
    if (ret != 0) printf_debug("aio_submit_cmd returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

// Wait for all (AND) or at least one (OR) to finish
#define SCE_KERNEL_AIO_WAIT_AND 0x01
#define SCE_KERNEL_AIO_WAIT_OR  0x02

typedef uint32_t useconds_t;

int32_t aio_multi_wait(
    SceKernelAioSubmitId ids[],
    uint32_t num_ids,
    SceKernelAioError aio_errors[],
    uint32_t mode, // SCE_KERNEL_AIO_WAIT_*
    useconds_t *usec
)
{
    int32_t ret = PS::Breakout::call(
        // LIBKERNEL(LIB_KERNEL_SCE_KERNEL_AIO_WAIT_REQUESTS),
        syscall_wrappers[SYS_AIO_MULTI_WAIT],
        PVAR_TO_NATIVE(ids),
        num_ids,
        PVAR_TO_NATIVE(aio_errors),
        mode,
        PVAR_TO_NATIVE(usec)
    );
    if (ret != 0) printf_debug("aio_multi_wait returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

int32_t aio_multi_delete(
    SceKernelAioSubmitId ids[],
    uint32_t num_ids,
    SceKernelAioError aio_errors[]
)
{
    int32_t ret = PS::Breakout::call(
        // LIBKERNEL(LIB_KERNEL_SCE_KERNEL_AIO_DELETE_REQUESTS),
        syscall_wrappers[SYS_AIO_MULTI_DELETE],
        PVAR_TO_NATIVE(ids),
        num_ids,
        PVAR_TO_NATIVE(aio_errors)
    );
    if (ret != 0) printf_debug("aio_multi_delete returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

int32_t aio_multi_cancel(
    SceKernelAioSubmitId ids[],
    uint32_t num_ids,
    SceKernelAioError aio_errors[]
)
{
    int32_t ret = PS::Breakout::call(
        // LIBKERNEL(LIB_KERNEL_SCE_KERNEL_AIO_CANCEL_REQUESTS),
        syscall_wrappers[SYS_AIO_MULTI_CANCEL],
        PVAR_TO_NATIVE(ids),
        num_ids,
        PVAR_TO_NATIVE(aio_errors)
    );
    if (ret != 0) printf_debug("aio_multi_cancel returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

int32_t aio_multi_poll(
    SceKernelAioSubmitId ids[],
    uint32_t num_ids,
    SceKernelAioError aio_errors[]
)
{
    int32_t ret = PS::Breakout::call(
        // LIBKERNEL(LIB_KERNEL_SCE_KERNEL_AIO_POLL_REQUESTS),
        syscall_wrappers[SYS_AIO_MULTI_POLL],
        PVAR_TO_NATIVE(ids),
        num_ids,
        PVAR_TO_NATIVE(aio_errors)
    );
    if (ret != 0) printf_debug("aio_multi_poll returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

#pragma endregion

#pragma region AIO helpers

// Helper to spray AIO requests
// Defaults to `multi` flag enabed, `cmd` set to read
// If `mutli` is true, allocate `loops * num_reqs` sized `ids` buffer
void spray_aio(
    SceKernelAioSubmitId* ids,
    uint32_t loops,
    SceKernelAioRWRequest* reqs,
    uint32_t num_reqs,
    bool multi = true,
    uint32_t cmd = SCE_KERNEL_AIO_CMD_READ
)
{
    if (multi) cmd |= SCE_KERNEL_AIO_CMD_MULTI;
    uint32_t step = multi ? num_reqs : 1;
    for (uint32_t i = 0, idx = 0; i < loops; i++) {
        aio_submit_cmd(
            cmd,
            reqs,
            num_reqs,
            SCE_KERNEL_AIO_PRIORITY_HIGH,
            &ids[idx]
        );
        // If `multi` is true, we push x(num_reqs) entries to `ids` rather than 1
        // Thus we increment `idx` by `num_reqs` to skip to empty slots
        idx += step;
    }
}

// Helper to cancel AIOs (cancel)
void cancel_aios(SceKernelAioSubmitId* ids, uint32_t num_ids)
{
    uint32_t rem = num_ids;
    while (rem)
    {
        uint32_t len = (rem < MAX_REQS) ? rem : MAX_REQS;
        rem -= len;
        SceKernelAioSubmitId* addr = &ids[num_ids - rem - len];
        aio_multi_cancel(addr, len, aio_errs);
    }
}

// Helper to free AIOs (cancel, poll, delete)
void free_aios(SceKernelAioSubmitId* ids, uint32_t num_ids)
{
    uint32_t rem = num_ids;
    while (rem)
    {
        uint32_t len = (rem < MAX_REQS) ? rem : MAX_REQS;
        rem -= len;
        SceKernelAioSubmitId* addr = &ids[num_ids - rem - len];
        aio_multi_cancel(addr, len, aio_errs);
        aio_multi_poll(addr, len, aio_errs);
        aio_multi_delete(addr, len, aio_errs);
    }
}

// Helper to free AIOs (poll, delete)
void free_aios2(SceKernelAioSubmitId* ids, uint32_t num_ids)
{
    uint32_t rem = num_ids;
    while (rem)
    {
        uint32_t len = (rem < MAX_REQS) ? rem : MAX_REQS;
        rem -= len;
        SceKernelAioSubmitId* addr = &ids[num_ids - rem - len];
        aio_multi_poll(addr, len, aio_errs);
        aio_multi_delete(addr, len, aio_errs);
    }
}

#pragma endregion

#pragma region Pad helpers

// Array of *rainbow* colors (R, G, B, A)
// Thanks @Dr.Yenyen
const uint8_t pad_colors[][4] = {
    {0x19, 0xfc, 0x72, 0xff}, // #19fc72/4
    {0xfa, 0x19, 0x5d, 0xff}, // #fa195d
    {0x25, 0x18, 0xfc, 0xff}, // #2518fc
    {0xfb, 0xc1, 0x1d, 0xff}, // #fbc11d
    {0xfa, 0x92, 0x1b, 0xff}, // #fa921b
    {0x18, 0xc9, 0xfe, 0xff}, // #18c9fe
    {0x25, 0x18, 0xfc, 0xff}, // #2518fc
    {0xfb, 0x19, 0x5c, 0xff}, // #fb195c/d
    {0xe5, 0x1a, 0xfa, 0xff}, // #e51afa
    {0x18, 0xc9, 0xfe, 0xff}, // #18c9fe
    {0x27, 0x19, 0xfd, 0xff}, // #2719fd
    {0x1a, 0xc8, 0xfc, 0xff}, // #1ac8fc
    {0x7e, 0xfc, 0x1b, 0xff}, // #7efc1b
    {0xfa, 0xc3, 0x1c, 0xff}, // #fac31c
    {0xe4, 0x1a, 0xfb, 0xff}, // #e41afb
};

void sleep_ms(uint32_t ms)
{
    PS::Sce::Kernel::Usleep(ms * 1000); // Usleep expects microseconds
}

void cycle_pad_colors(uint32_t delay_ms = 75)
{
    const size_t num_colors = sizeof(pad_colors) / sizeof(pad_colors[0]);
    for (uint32_t i = 0; i < num_colors; ++i) {
        PS::PadSetLightBar(
            pad_colors[i][0],
            pad_colors[i][1],
            pad_colors[i][2],
            pad_colors[i][3]
        );
        sleep_ms(delay_ms);
    }
}

#pragma endregion
