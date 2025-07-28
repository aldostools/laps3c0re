    .section .rodata
    .global payload_start
    .global payload_end

payload_start:
    .incbin "payload.bin"
payload_end:
