###Contribution
**Arshad**:Documentation, some error handling and number of page faults and calculation of internal fragmentation<br/>
**Sanchay**: Rest Of The Loader

**Github Repository: [Sanchay117/OS-Smart-Loader: Assignment 4 Of Operating Systems Course](https://github.com/Sanchay117/OS-Smart-Loader)**

**Components**

1. **ELF Header Reading**
- **Function**: `void read\_elf\_header()`
- Reads the ELF header from the executable and verifies its validity by checking the magic numbers (0x7f, E, L, F).
- Exits with an error if the header is invalid.
2. **Program Header Reading**
- **Function**: `void read\_programm\_header(const int i, const unsigned short int programm\_header\_size)`
- Reads the program headers sequentially to identify segment details.
3. **Page Fault Handler**
- **Function**: `void handle\_page\_fault(int signum, siginfo\_t \*sig, void\* context)`
- Catches a segmentation fault and identifies the address causing the fault.
- Allocates a 4KB page at the fault address using mmap.
- Reads data from the file into the allocated memory page.
- Tracks internal fragmentation if the segment size does not align with 4KB boundaries.
4. **Loader Cleanup**
- **Function**: `void loader\_cleanup()`
- Frees allocated memory and unmaps segments using munmap.
5. **Main Execution Logic**
- **Entry point**: `int main(int argc, char\*\* argv)`
- Sets up the SIGSEGV signal handler.
- Reads the ELF and program headers.
- Begins execution by typecasting the entry point address and invoking it as a function.

**Signal Handling**

**Setup**

- **Function**:` void setup\_signal\_handler()`
- Configures a signal handler for SIGSEGV using sigaction.
- Calls handle\_page\_fault() when a segmentation fault occurs.

**Page Fault Logic**

- The handler checks which program segment covers the faulting address.
- Aligns the faulting address to a 4KB boundary and allocates memory with mmap.
- Reads the relevant data from the executable into the allocated memory.
- Reports page allocations and internal fragmentation.

**Memory Management**

**Allocation**

- Pages are allocated using mmap with the MAP\_FIXED | MAP\_PRIVATE | MAP\_ANONYMOUS flags.
- Ensures allocation is done only when needed, minimizing memory usage.

**Cleanup**

- Unmaps memory after program execution using munmap.
- Frees dynamically allocated data structures (e.g., ELF header).

**Error Handling**

- Validates ELF file format and program header reading.
- Checks the success of mmap and lseek operations.
- Exits gracefully if any error occurs during reading or memory mapping.
