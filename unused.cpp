struct thr_param_s
{
    ptr64_t start_func; // void (*start_func)(void *);
    ptr64_t arg; // void *arg;
    ptr64_t stack_base; // char *stack_base;
    size_t stack_size;
    ptr64_t tls_base; // char *tls_base;
    size_t tls_size;
    ptr64_t child_tid; // long *child_tid;
    ptr64_t parent_tid; // long *parent_tid;
    int32_t flags;
    uint8_t _pad[4];
    ptr64_t rtp; // rtprio_s *rtp;
    ptr64_t name;
    ptr64_t unk1;
    ptr64_t unk2;
};

int32_t thr_new(thr_param_s *param)
{
    printf_debug("syscall_wrappers[SYS_THR_NEW]: %p\n", (void*)syscall_wrappers[SYS_THR_NEW]);
    printf_debug("sizeof(thr_param_s): %u\n", sizeof(thr_param_s));
    int32_t ret = PS::Breakout::call(
        syscall_wrappers[SYS_THR_NEW],
        PVAR_TO_NATIVE(param),
        sizeof(thr_param_s) // param_size
    );
    if (ret < 0) printf_debug("thr_new failed: %d\n", ret);
    return ret;
}

// log sigjmp_buf fields
printf_debug("sigjmp_buf:\n");
printf_debug("  rip: %p\n", (void*)env.rip);
printf_debug("  rbx: %p\n", (void*)env.rbx);
printf_debug("  rsp: %p\n", (void*)env.rsp);
printf_debug("  rbp: %p\n", (void*)env.rbp);
printf_debug("  r12: %p\n", (void*)env.r12);
printf_debug("  r13: %p\n", (void*)env.r13);
printf_debug("  r14: %p\n", (void*)env.r14);
printf_debug("  r15: %p\n", (void*)env.r15);
printf_debug("  fpu_control: %04x\n", (uint16_t)env.fpu_control);
printf_debug("  mxcsr: %04x\n", (uint16_t)env.mxcsr);
printf_debug("  sigmask: [%p, %p]\n", (void*)env.sigmask[0], (void*)env.sigmask[1]);
printf_debug("  savesigs: %d\n", (uint32_t)env.savesigs);
printf_debug("  __pad: [%02x, %02x, %02x, %02x]\n",
    env._pad[0], env._pad[1], env._pad[2], env._pad[3]);


uint64_t racer_chain(void *arg)
{
    ROP_Chain chain = ROP_Chain(0x4000);

    if (!chain.is_initialized())
    {
        printf_debug("Failed to initialize ROP chain!\n");
        return -1;
    }

    // chain.push(GADGET(RET));
    // chain.push_padding(1);
    chain.set_RAX(1337);
    uint64_t value = 0;
    chain.get_result(&value);

    chain.set_RDX(0);
    chain.set_RDI(7);
    chain.set_RSI(PVAR_TO_NATIVE("Hello, racer!\n"));
    chain.push(LIBKERNEL(LIB_KERNEL_MDBG_SERVICE));

    char txt1[5] = "0000";
    chain.set_RDX(4);
    chain.set_RDI(PVAR_TO_NATIVE(txt1));
    chain.set_RSI(PVAR_TO_NATIVE("1111"));
    chain.push(EBOOT(EBOOT_MEMCPY_STUB));

    char txt2[5] = "0002";
    chain.set_RDX(4);
    chain.set_RDI(PVAR_TO_NATIVE(txt2));
    chain.set_RSI(PVAR_TO_NATIVE("2222"));
    chain.push(EBOOT(EBOOT_MEMCPY_STUB));

    ScePthread thread = 0;
    if (chain.execute(&thread) != 0)
    {
        printf_debug("Failed to execute ROP chain!\n");
        chain.clear();
        return -1;
    }
    printf_debug("Thread created successfully with ID: %p\n", thread);

    if (scePthreadJoin(thread, 0) != 0) // Wait for the thread to finish
    {
        printf_debug("Failed to join thread!\n");
        chain.clear();
        return -1;
    }

    printf_debug("Thread exited.\n");

    printf_debug("%s\n", txt1);
    printf_debug("%s\n", txt2);
    printf_debug("value: %d\n", value);

    chain.clear();

    return 0;
}


thr_chain.push_call(
    EBOOT(EBOOT_WRITE_STUB),
    PS::Debug.sock,
    PVAR_TO_NATIVE("test\n"),
    5
);
