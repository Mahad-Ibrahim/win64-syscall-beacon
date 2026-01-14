# Project Tartarus: Advanced Windows Implant Architecture
*A custom-built Adversary Emulation framework focusing on x64 syscall evasion and OS internals.*

#### Project Status: Complete APT Simulation

While this repository hosts the source code for the core Implant Engine (Tartarus Gate) and the Assembly Network Stager, these are individual components of a larger, fully integrated Advanced Persistent Threat (APT) simulation.

The complete project—including the multi-hop C2 infrastructure, persistence mechanisms, and logic integration—is fully functional and complete. However, due to the sensitive nature of the code and the potential for misuse, the full source code is hosted in a private repository.

I am happy to provide access to the full private repository or a walkthrough of the complete architecture upon request for interview and verification purposes. Please contact me directly to arrange access.

# Proof of Concept
A PoC x64 Windows implant that makes an HTTP POST request using direct syscalls and manual [PEB](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb) walking. Made to bypass user-mode API hooks by EDR/AV.

Note: This project was made for educational and research purposes only, attempting to showcase modern evasion techniques and Windows OS internals.
## Key Technical Features

* **Direct Syscall Execution:** Uses the [Tartarus Gate/Hell's Gate](https://redops.at/en/blog/exploring-hells-gate) technique to find System Service Numbers (SSNs) while the program runs. This allows it to bypass antivirus hooks on `Nt*` functions.
* **Position Independent Code (PIC):** The code works from any memory address. It manually walks through the PEB and Kernel32.dll to find [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress).
* **Wininet via Assembly:** It uses `GetProcAddress` to find the addresses of key networking functions.

# x64 Tartarus Gate

![Language](https://img.shields.io/badge/Language-C%20%2F%20x64_Assembly-blue) ![Platform](https://img.shields.io/badge/Platform-Windows-0078D6) ![Technique](https://img.shields.io/badge/Technique-Direct_Syscalls-red)

The source code for this is inside `main.c`.

### 1. The PEB Walk

To avoid calling functions that might be monitored by antivirus software (AV/EDR), the loader does the following steps instead of using standard APIs:

1.  **Reads the GS register** to find the [TEB (Thread Environment Block)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb).
    > *NOTE: In x86_64 Windows, the GS register is used to point to the current Thread Environment Block (TEB).*
2.  **Finds the PEB pointer** inside the TEB at offset `0x60`.
    > *NOTE: At offset 60h, there is a pointer named `PPEB ProcessEnvironmentBlock`.*
3.  **Finds the `PPEB_LDR_DATA`** inside the PEB.
    > *[Reference: PEB_LDR_DATA Structure](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)*
4.  **Loops through the `InMemoryOrderModuleList`** to find the target DLL.
    > *NOTE: The `InMemoryOrderModuleList` is a structure inside `PEB_LDR_DATA`. It is a doubly linked list that connects all loaded modules. This is known as an [intrusive linked list](https://www.data-structures-in-practice.com/intrusive-linked-lists/).*
5.  **Gets the Base Address:** Once it identifies the correct DLL (using `UNICODE_STRING FullDllName`), the loader gets the `PVOID DllBase` from the `_LDR_DATA_TABLE_ENTRY`.

### 2. Syscall Resolution

After finding the DLL base address, the loader reads the Export Address Table (EAT) of the PE file.

> *NOTE: The steps below explain how we move through the PE file. For a complete guide on the PE File format, I recommend [0xRick's Blog](https://0xrick.github.io/win-internals/pe2/).*

1.  **Bypass the [DOS headers](https://0xrick.github.io/win-internals/pe3/)** by reading the 4-byte value at offset `0x3C`.
    > *NOTE: At `0x3C`, there is an offset called `e_lfanew`. It acts like an [RVA](https://tech-zealots.com/malware-analysis/understanding-concepts-of-va-rva-and-offset/) to the [NtHeaders](https://0xrick.github.io/win-internals/pe4/).*
2.  **Find the Optional Header:** From `NtHeaders`, we go to the `IMAGE_OPTIONAL_HEADER64`.
    > *NOTE: The [IMAGE_OPTIONAL_HEADERS64](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64) is a structure inside `NtHeaders`. Its size changes depending on the architecture (32-bit vs 64-bit).*
3.  **Access Data Directories:** Inside the Optional Header, we look for `IMAGE_DATA_DIRECTORY DataDirectory`.
    > *NOTE: The [IMAGE_DATA_DIRECTORY](https://0xrick.github.io/win-internals/pe5/) contains addresses (RVAs) to different Data Directories. We only need Index 0: The Export Directory.*
4.  **Read the Export Table:** We calculate the offset from `DataDirectory[0]` to land at the [Export Address Table (EAT)](https://ferreirasc.github.io/PE-Export-Address-Table/).
5.  **Read EAT Arrays:** We look at three arrays to find the SSNs:
    * `AddressOfFunctions`
    * `AddressOfNames`
    * `AddressOfNameOrdinals`
6.  **Find Function Address:**
    1.  Find the function name in `AddressOfNames`.
    2.  Get the index number from `AddressOfNameOrdinals`.
    3.  Use that index in `AddressOfFunctions` to get the function's RVA.
7.  **The "Gate" Check (Tartarus Gate):**
    * We calculate where the function is in memory.
    * **Hook Check:** We check the first few bytes. If the code starts with a `jmp` (which means it is hooked), we do not use it.
    * **Neighbor Scan:** We scan memory 32 bytes up and down (the size of a syscall stub) to find a "clean" neighbor that is not hooked.
    * **SSN Calculation:** Once we find a clean neighbor, we calculate the SSN of our target function by doing simple addition or subtraction based on the distance.

### 3. Syscall Execution

After we have the SSN, we execute it using a custom assembly stub.

1.  **ABI Compliance:** We follow the [Windows x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170).
2.  **Register Adjustment:** The `syscall` instruction overwrites `rcx` (it saves `rip` to `rcx`). Because of this, we must move the first argument from `rcx` to `r10` before we run the command.
3.  **Execution:** We run the `syscall` instruction.

## 🔧 Required Functions for Shellcode

Using the **Tartarus Gate** technique described above, the beacon dynamically finds the System Service Numbers (SSNs) for four specific functions. These functions are necessary to execute the shellcode safely:

1.  **`NtAllocateVirtualMemory`**
    * **Purpose:** Allocates a new space in memory.
    * **Why:** We need a place to put our shellcode. We cannot just write it anywhere, or the program will crash.

2.  **`NtWriteVirtualMemory`**
    * **Purpose:** Writes data into the allocated memory.
    * **Why:** This function copies our shellcode (payload) into the empty space we just created.

3.  **`NtProtectVirtualMemory`**
    * **Purpose:** Changes the permissions of the memory.
    * **Why:** By default, memory is usually "Read/Write". To run code, we must change it to "Read/Execute" (RX). This step is critical to avoid Data Execution Prevention (DEP) crashes.

4.  **`NtCreateThreadEx`**
    * **Purpose:** Starts a new thread.
    * **Why:** This executes the shellcode in a separate thread, allowing the beacon to run the payload without freezing or crashing the main process.
  

# x64 WinINet Stager (PoC)

![Language](https://img.shields.io/badge/Language-MASM_x64-red) ![Platform](https://img.shields.io/badge/Platform-Windows-0078D6) ![Technique](https://img.shields.io/badge/Technique-Shellcode_Style-yellow)

The source code for this is inside `httpRequestSenderShellcode.asm`.

This is a pure x64 Assembly program that sends an HTTP POST request. It is a Proof-of-Concept (PoC) that shows how to use Windows APIs (`WinINet`) without using standard imports or the `.data` section.

It works like **shellcode**: it finds system DLLs and functions manually while the program is running.

## Key Features

* **No Static Imports:** The program has an empty Import Address Table (IAT). It does not link to `kernel32.lib` or `wininet.lib`.
* **Manual PEB Walk:** It finds `kernel32.dll` by reading the Process Environment Block (PEB) using the `GS` register.
* **Custom Export Parsing:** It uses a **ROR13 Hashing** algorithm to find `GetProcAddress` in the Kernel32 Export Address Table (EAT).
* **Stack Strings:** All strings (like DLL names, function names, and HTTP headers) are built on the stack while the program runs. This means there are no readable strings in the file, which makes analysis harder.

## How It Works

1.  **Find Kernel32:** It walks through the PEB (`GS:[60h]`) to find where `kernel32.dll` is loaded in memory.
2.  **Find GetProcAddress:** It reads the EAT of Kernel32 to find the `GetProcAddress` function using a hash.
3.  **Load WinINet:** It uses `GetProcAddress` to find `LoadLibraryA`, and then loads `wininet.dll`.
4.  **Get HTTP Functions:** It dynamically finds the addresses for:
    * `InternetOpenA`
    * `InternetConnectA`
    * `HttpOpenRequestA`
    * `HttpSendRequestA`
5.  **Send Beacon:** It sends an HTTP `POST` request to a server.

## Documentation

The source code `main.asm` has **many comments**. These comments explain the stack management and structure offsets step-by-step.

> **Please read the comments in the source file for a detailed explanation of the registers and memory management.**

# DISCLAIMER
This software is provided for educational purposes only. It demonstrates operating system internals and modern evasion techniques. The author is not responsible for any misuse of this code. Do not use this on systems you do not own or have explicit permission to test.
