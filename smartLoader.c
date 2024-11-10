#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <signal.h>
#include <bits/sigaction.h>

#define MAX_SEGMENTS 250
#define PAGE_SIZE 4096

Elf32_Ehdr *ehdr; // pointer to ELF header struct
Elf32_Phdr *phdr; // pointer to Programm header struct
int seg_ptr = 0;
char* ELF_file_name;

typedef struct{
  void* address;
  size_t segment_size;
  size_t file_size;
  size_t allocated;
  void *file_data;
} SegmentMap;

SegmentMap segments_for_cleanup[MAX_SEGMENTS];

int fd;
void* entry_pt_addr;

// read ELF Header
void read_elf_header(){
  ehdr = (Elf32_Ehdr*)(malloc(sizeof(Elf32_Ehdr))); // (Elf32_Ehdr*)-> typecasts void*

  if(read(fd,ehdr,sizeof(Elf32_Ehdr))!= sizeof(Elf32_Ehdr)){
  	printf("Error: Couldn't read ELF header\n");
  	exit(1);
  }

  if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' || ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F') {
    printf("Error: %s is not an ELF file.\n", ELF_file_name);
    exit(1);
  }
}

void loader_cleanup() {
  // free(phdr); -> Already Done!
  free(ehdr);
  for(int i = 0;i<MAX_SEGMENTS;i++){
    if(segments_for_cleanup[i].address!=NULL){
      if(munmap(segments_for_cleanup[i].address, segments_for_cleanup[i].segment_size)==-1){
        printf("Munmap for freeing segment memory failed");
      }else {
        printf("Successfully unmapped segment at %p\n", segments_for_cleanup[i].address);
      }
    }else{
      break;
    }
  }
}

void read_programm_header(const int i,const unsigned short int programm_header_size){
  phdr = (Elf32_Phdr*)(malloc(sizeof(Elf32_Phdr)));
  lseek(fd,ehdr->e_phoff + i*programm_header_size,SEEK_SET);
  
  if (read(fd, phdr, sizeof(Elf32_Phdr)) != sizeof(Elf32_Phdr)) {
    printf("Error: Couldn't read program header\n");
    exit(1);
  }
  
  // printf("Program Header %d:\n", i);
  // printf("  Type: %u\n", phdr->p_type);
  // printf("  Offset: %u\n", phdr->p_offset);
  // printf("  Virtual Address: %u\n", phdr->p_vaddr);
  // printf("  File Size: %u\n", phdr->p_filesz);
  // printf("  Memory Size: %u\n", phdr->p_memsz);
  // printf("  Flags: %u\n", phdr->p_flags);
  // printf("  Alignment: %u\n", phdr->p_align);

  // printf("----------------------\n");
}

void handle_page_fault(int signum, siginfo_t *info, void *context) {
  void *fault_addr = info->si_addr;
  printf("PAGE FAULT\n");
  SegmentMap *target_segment = NULL;

  // Step 1: Find the segment that contains the fault address
  for (int i = 0; i < seg_ptr; i++) {
    void *segment_start = segments_for_cleanup[i].address;
    size_t segment_size = segments_for_cleanup[i].segment_size;

    if ((uintptr_t)fault_addr >= (uintptr_t)segment_start &&
      (uintptr_t)fault_addr < (uintptr_t)segment_start + segment_size) {
      target_segment = &segments_for_cleanup[i];
      break;
    }
  }

  if (!target_segment) {
    fprintf(stderr, "Fault address does not belong to any segment.\n");
    loader_cleanup();
    exit(EXIT_FAILURE);
  }

  // Step 2: Align fault address to the page boundary
  void *page_start = (void *)((uintptr_t)fault_addr & ~(PAGE_SIZE - 1));

  // Step 3: Calculate offset within segment and remaining size
  size_t offset_within_segment = (uintptr_t)page_start - (uintptr_t)target_segment->address;
  size_t remaining_size = target_segment->segment_size - offset_within_segment;
  size_t alloc_size = (remaining_size > PAGE_SIZE) ? PAGE_SIZE : remaining_size;

  // Step 4: Map the memory page
  if (mmap(page_start, alloc_size, PROT_READ | PROT_WRITE | PROT_EXEC,MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
    perror("mmap failed");
    exit(EXIT_FAILURE);
  }

  // Step 5: Copy data from the ELF file if within the file size
  if (offset_within_segment < target_segment->file_size) {
    size_t copy_size = (alloc_size > target_segment->file_size - offset_within_segment) 
    ? target_segment->file_size - offset_within_segment
    : alloc_size;

    memcpy(page_start, (char*)target_segment->file_data + offset_within_segment, copy_size);

    // Zero out any remaining space if `alloc_size` is greater than `copy_size`
    if (alloc_size > copy_size) {
      memset((char*)page_start + copy_size, 0, alloc_size - copy_size);
    }
  } else {
    // If beyond file size (for .bss-like sections), zero out the allocated memory
    memset(page_start, 0, alloc_size);
  }

  printf("Mapped and loaded page at %p (size: %zu bytes) for segment starting at %p\n",page_start, alloc_size, target_segment->address);
}


void map_segments(const unsigned short int programm_header_size){

  // loading
  void* VIRTUAL_MEMORY = mmap(NULL,phdr->p_memsz,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_ANONYMOUS|MAP_PRIVATE,0,0);

  if(VIRTUAL_MEMORY==MAP_FAILED){
    printf("Error Mapping memory\n");
    exit(1);
  }

  lseek(fd,phdr->p_offset,SEEK_SET);

  // Reading data
  if (read(fd, VIRTUAL_MEMORY, phdr->p_filesz) != phdr->p_filesz) {
    printf("Error reading segment data\n");
    exit(1);
  }

  // Zero out the rest of the memory if the segment is larger than the file size
  if (phdr->p_filesz < phdr->p_memsz) {
    memset((char*)VIRTUAL_MEMORY + phdr->p_filesz, 0, phdr->p_memsz - phdr->p_filesz);
  }

  printf("PT_LOAD Segment loaded at address %p\n", VIRTUAL_MEMORY);

  // loading done

  if (ehdr->e_entry >= phdr->p_vaddr && ehdr->e_entry < phdr->p_vaddr + phdr->p_memsz) {
    size_t offset_inside_segment = ehdr->e_entry - phdr->p_vaddr;
    entry_pt_addr = (char*) VIRTUAL_MEMORY + offset_inside_segment;
    printf("Entry point located at address %p\n", entry_pt_addr);
  }

  // free(VIRTUAL_MEMORY);
  // munmap(VIRTUAL_MEMORY,phdr->p_memsz);

  segments_for_cleanup[seg_ptr].address = VIRTUAL_MEMORY;
  // segments_for_cleanup[seg_ptr].space = phdr->p_memsz;
  seg_ptr++;
}

/*
 * Load and run the ELF executable file
*/

void load_and_run_elf(char** elf_file) {

  char* ELF_file_name = elf_file[1];
  // printf("%s %d\n",ELF_file_name,fd);
  
  unsigned short int programm_header_size = ehdr->e_phentsize;
  
  for(int i = 0;i<ehdr->e_phnum;i++){

    read_programm_header(i,programm_header_size);

    // now loading PT_LOAD

    if(phdr->p_type==PT_LOAD){
      // map_segments(programm_header_size);

      // Virtual address where the segment should be loaded
      void *segment_vaddr = (void *)phdr->p_vaddr;
      
      // Size of the segment in memory
      size_t segment_size = phdr->p_memsz;

      // Size of the segment in the file
      size_t file_size = phdr->p_filesz;

      printf("Segment virtual address: %p\n", segment_vaddr);
      printf("Segment size in memory: %zu bytes\n", segment_size);
      printf("Segment size in file: %zu bytes\n", file_size);

      segments_for_cleanup[seg_ptr].address = segment_vaddr;
      segments_for_cleanup[seg_ptr].segment_size = segment_size;
      segments_for_cleanup[seg_ptr].file_size = file_size;
      segments_for_cleanup[seg_ptr].allocated = 0;
      segments_for_cleanup[seg_ptr].file_data = phdr->p_offset;

      seg_ptr++;

      if (ehdr->e_entry >= phdr->p_vaddr && ehdr->e_entry < phdr->p_vaddr + phdr->p_memsz) {
        size_t offset_inside_segment = ehdr->e_entry - phdr->p_vaddr;
        entry_pt_addr = (char*) VIRTUAL_MEMORY + offset_inside_segment;
        printf("Entry point located at address %p\n", entry_pt_addr);
      }

      // Now you can use `segment_vaddr` and `segment_size` for mapping the segment
    }
    
    // not freeing this in loader_cleanup as pointer referencing a new address for every programm header
    free(phdr);
  }

  if (entry_pt_addr != NULL) {
        // Typecast the entry_point_address to a function pointer and call it
        int (*entry_func)() = (int (*)())entry_pt_addr;
        int result = entry_func();
        printf("--------------------------------------------\n");
        printf("User _start return value = %d\n", result);
        printf("--------------------------------------------\n");
    } else {
        printf("Error: Entry point not found in any segment\n");
    }
}

void setup_signal_handler() {
  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;  // Set to use siginfo_t for additional context
  sa.sa_sigaction = handle_page_fault;

  // Handle SIGSEGV for segmentation faults
  if (sigaction(SIGSEGV, &sa, NULL) == -1) {
    perror("Failed to set up SIGSEGV handler");
    exit(EXIT_FAILURE);
  }

  // handle SIGINT for graceful exits on Ctrl+C
  signal(SIGINT, [](int signum){
    loader_cleanup();
    exit(0);
  });
}

int main(int argc, char** argv) {

  setup_signal_handler();

  /*printf("Number of arguments: %d\n", argc);
  for (int i = 0; i < argc; i++) {
    printf("Argument %d: %s\n", i, argv[i]);
  }*/

  if(argc != 2) {
    printf("Usage: %s <ELF Executable> \nYou need to provide ELF File as an argument\n",argv[0]);
    exit(1);
  }else{
    ELF_file_name = argv[1];
  }

  // printf("%s\n",ELF_file_name);

  // 1. carry out necessary checks on the input ELF file

  // Checking if file exists
  if (access(ELF_file_name, F_OK) != 0) {
    printf("Error: File %s does not exist.\n", ELF_file_name);
    exit(1);
  }

	// Checking if we have access to read said file
  fd = open(ELF_file_name, O_RDONLY);
  if (fd < 0) {
 	printf("Error opening file\n");
 	exit(1);
  }

  // Checking if the said file is an ELF and reading ELF header

  read_elf_header();  

  // 2. passing it to the loader for carrying out the loading/execution
  // Now if we come so far, we are sure that we have an ELF!

  // printf("YIPEE! [File is valid and ELF header is loaded ] (for debugging purposes)\n");
  load_and_run_elf(argv);
  
  // 3. invoke the cleanup routine inside the loader  
  loader_cleanup();

  if (close(fd) < 0) {
	printf("Error closing file\n");
	exit(1);
  }

  // free(ehdr);

  return 0;
}