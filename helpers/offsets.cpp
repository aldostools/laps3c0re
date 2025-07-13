#pragma once


#if defined(PS4) && PS4

// proc
#define PROC_FD 0x48
#define PROC_PID 0xb0
#define PROC_VM_SPACE 0x200
// filedesc
#define FILEDESC_OFILES 0x0
#define SIZEOF_OFILES 0x8
// file
#define FILE_FDATA 0x0
// pipe
#define SIZEOF_PIPEBUF 0x18
// socket
#define SOCK_PCB 0x18
// inpcb
#define PCB_PKTINFO 0x118
// pktopts
#define TCLASS_OFFSET 0xb0

#if defined(FIRMWARE) && FIRMWARE == 1001

#define EVF_OFFSET 0x7b5133

#endif

#elif defined(PS5) && PS5

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
#define SIZEOF_PIPEBUF 0x18 // Double-check this !!!
// socket
#define SOCK_PCB 0x18 // Double-check this !!!
// inpcb
#define PCB_PKTINFO 0x118 // Double-check this !!!
// pktopts
#define TCLASS_OFFSET 0xc0

#endif
