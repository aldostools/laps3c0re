#pragma once


#define BASE 0xffffffff82200000
#define PAGE_SIZE 0x4000
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))

#if defined(PS4) && PS4

// Offsets
// pcpu
#define PCPU_CURTHREAD 0x0
// thread
#define TD_PROC 0x8
#define TD_KSTACK 0x3F0
// kstack (assuming it occupies 1 PAGE_SIZE)
#define KSTACK_FRAME_OFFSET 0x3AB0
// proc
#define PROC_UCRED 0x40
#define PROC_FD 0x48
#define PROC_PID 0xb0
#define PROC_VM_SPACE 0x200
// filedesc
#define FILEDESC_OFILES 0x0
#define SIZEOF_OFILES 0x8
#define FILEDESC_RDIR 0x10
#define FILEDESC_JDIR 0x18
// file
#define FILE_FDATA 0x0
// pipe
#define PIPEBUF_BUFFER 0x10
// socket
#define SOCK_PCB 0x18
// inpcb
#define PCB_PKTINFO 0x118
// pktopts
#define IPV6_PKTINFO_OFFSET 0x10
#define TCLASS_OFFSET 0xb0
#define IP6PO_RTHDR_OFFSET 0x68

#if (FIRMWARE == 1000 || FIRMWARE == 1001)

// Kernel addresses
#define K_EVF_OFFSET 0x7b5133
#define K_CPUID_TO_PCPU 0x21e47f0
#define K_PRISON0 0x111b8b0
#define K_ROOTVNODE 0x1b25bd0
#define K_SYS_READ_RET 0x25fdfa
#define K_SYS_READ_RET_SKIP_CHECK 0x25fe03
#define K_WRITE 0x2602b0
#define K_KERNEL_MAP 0x227bef8
#define K_XILL 0x2d2370
#define K_SETIDT 0x7b460
#define K_KMEM_ALLOC 0x33b040
// (03)
#define K_KMEM_ALLOC_PATCH1 0x33b10c
// (03)
#define K_KMEM_ALLOC_PATCH2 0x33b114
#define K_MEMCPY 0x472d20

// Gadgets
// ret (c3)
#define G_RET 0x8e0
// pop rdi ; ret (5f c3)
#define G_POP_RDI_RET 0x310c4e
// pop rsi ; ret (5e c3)
#define G_POP_RSI_RET 0x983e0
// pop rdx ; ret (5a c3)
#define G_POP_RDX_RET 0x2029b2
// pop rcx ; ret (59 c3)
#define G_POP_RCX_RET 0x983ba
// pop r8 ; pop rbp ; ret (41 58 5d c3)
#define G_POP_R8_POP_RBP_RET 0x1bcfa7
// pop rax ; ret (58 c3)
#define G_POP_RAX_RET 0x9974f
// pop rbp ; ret (5d c3)
#define G_POP_RBP_RET 0x8df
// pop rsp ; ret (5c c3)
#define G_POP_RSP_RET 0x97719
// mov byte ptr [rcx], al ; ret (88 01 c3)
#define G_MOV_BYTE_PTR_RCX_AL_RET 0x2f0448
// pop qword ptr [rdx] ; ret (8f 02 c3)
#define G_POP_QWORD_PTR_RDX_RET 0xacca32
// mov qword ptr [rdx], rax ; pop rbp ; ret (48 89 02 5d c3)
#define G_MOV_QWORD_PTR_RDX_RAX_POP_RBP_RET 0x1d790a
// mov cr0, rsi ; test rsi, 0x10000 ; jnz 2 ; ud2 ; mov eax, 1 ; ret 
// (0f 22 c6 48 f7 c6 00 00 01 00 75 02 0f 0b b8 01 00 00 00 c3)
#define G_MOV_CR0_RSI_UD2_MOV_EAX_1_RET 0x176089
// add rsp, 0x28 ; pop rbp ; ret (48 83 c4 28 5d c3)
#define G_ADD_RSP_28_POP_RBP_RET 0x4d0d0a

#elif FIRMWARE == 1100

// Kernel addresses
#define K_EVF_OFFSET 0x7fc26f
#define K_CPUID_TO_PCPU 0x212c840
#define K_PRISON0 0x111f830
#define K_ROOTVNODE 0x2116640
#define K_SYS_READ_RET 0xdcdaa
#define K_SYS_READ_RET_SKIP_CHECK 0xdcdb3
#define K_WRITE 0xdd260
#define K_KERNEL_MAP 0x21ff130
#define K_XILL 0x2d2370
#define K_SETIDT 0x25bdb0
#define K_KMEM_ALLOC 0x245e10
// (03)
#define K_KMEM_ALLOC_PATCH1 0x245edc
// (03)
#define K_KMEM_ALLOC_PATCH2 0x245ee4
#define K_MEMCPY 0x2dddf0

// Gadgets
// ret (c3)
#define G_RET 0x7e4
// pop rdi ; ret (5f c3)
#define G_POP_RDI_RET 0x3f38ed
// pop rsi ; ret (5e c3)
#define G_POP_RSI_RET 0x4a6a9
// pop rdx ; ret (5a c3)
#define G_POP_RDX_RET 0xa4762
// pop rcx ; ret (59 c3)
#define G_POP_RCX_RET 0x1170a
// pop r8 ; pop rbp ; ret (41 58 5d c3)
#define G_POP_R8_POP_RBP_RET 0x4ae4d
// pop rax ; ret (58 c3)
#define G_POP_RAX_RET 0x1172e
// pop rbp ; ret (5d c3)
#define G_POP_RBP_RET 0x8df
// pop rsp ; ret (5c c3)
#define G_POP_RSP_RET 0x51ffb
// mov byte ptr [rcx], al ; ret (88 01 c3)
#define G_MOV_BYTE_PTR_RCX_AL_RET 0x16ae58
// pop qword ptr [rdx] ; ret (8f 02 c3)
#define G_POP_QWORD_PTR_RDX_RET 0xace252
// mov qword ptr [rdx], rax ; pop rbp ; ret (48 89 02 5d c3)
#define G_MOV_QWORD_PTR_RDX_RAX_POP_RBP_RET 0x2d881
// mov cr0, rsi ; test rsi, 0x10000 ; jnz 2 ; ud2 ; mov eax, 1 ; ret 
// (0f 22 c6 48 f7 c6 00 00 01 00 75 02 0f 0b b8 01 00 00 00 c3)
#define G_MOV_CR0_RSI_UD2_MOV_EAX_1_RET 0x2f1299
// add rsp, 0x28 ; pop rbp ; ret (48 83 c4 28 5d c3)
#define G_ADD_RSP_28_POP_RBP_RET 0x4cb2da

#endif

#elif defined(PS5) && PS5

// pcpu
#define PCPU_CURTHREAD 0x0 // Double-check this !!!
// thread
#define TD_PROC 0x8 // Double-check this !!!
// proc
#define PROC_FD 0x48
#define PROC_PID 0xbc
#define PROC_VM_SPACE 0x200
// filedesc
#define FILEDESC_OFILES 0x8
#define SIZEOF_OFILES 0x30
// file
#define FILE_FDATA 0x0 // Double-check this !!!
// pipe
#define PIPEBUF_BUFFER 0x10 // Double-check this !!!
// socket
#define SOCK_PCB 0x18 // Double-check this !!!
// inpcb
#define PCB_PKTINFO 0x118 // Double-check this !!!
// pktopts
#define IPV6_PKTINFO_OFFSET 0x10 // Double-check this !!!
#define TCLASS_OFFSET 0xc0
#define IP6PO_RTHDR_OFFSET 0x68 // Double-check this !!!


#endif
