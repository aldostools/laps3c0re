# 0x80
* double_free_reqs()
- Double free aio_entry [PANIC]
- Allocate rthdrs (rthdr_sds[0]) [HALF_RESTORE]
- Alias rthdrs (rthdr_sds[1]) [RESTORE]
* leak_kernel_addrs()
- Free rthdrs (rthdr_sds[1]) [HALF_RESTORE]
- Alias evf (s2.evf) [RESTORE]
* Memory leaks with rthdr_sds[0] and s2.evf pair:
* Kernel base, the address of the 0x80 block itself,
* the address of reqs1 (the 0x100 block)

* double_free_reqs1()
- Free evf (s2.evf) [HALF_RESTORE]
- Alias aio_entry (?req_id) [RESTORE]
- Free rthdrs (rthdr_sds[0]) [PANIC]
- Alias rthdrs (?dirty_sd) [RESTORE]
- Delete aio_entry (req_id) [HALF_RESTORE]
  - Free req_id->ar2_batch [PANIC??][WRONG]
    - ar2_batch is aio_entry + 0x28??!
- Set dirty_sd's pktopts.rthdr to 0 [FULL_RESTORE]

# 0x100
* double_free_reqs1()
- Double free reqs1 [PANIC]
- Allocate pktopts (pktopts_sds[0]) [HALF_RESTORE]
- Allocate pktopts (pktopts_sds[1]) [RESTORE]
- Free pktopts (pktopts_sds[1]) [HALF_RESTORE]
- Allocate rthdr (s4.reclaim_sd) [RESTORE]
- Set reclaim_sd's pktopts.rthdr to 0 [FULL_RESTORE]

# pipe
* Override pipe_buf.buffer [PANIC]
* Restore pipe_buf.buffer [RESTORE??]

