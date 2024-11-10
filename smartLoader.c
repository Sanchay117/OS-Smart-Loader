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
Elf32_Phdr* segments[MAX_SEGMENTS];
int ptr = 0;

int fd;
void* entry_pt_addr;
int page_faults = 0,page_allocations = 0;
int internal_fragmentation = 0;

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
  for(int i = 0;i<seg_ptr;i++){
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

  for(int i = 0;i<ptr;i++){
    free(segments[i]);
  }
}

void read_programm_header(const int i,const unsigned short int programm_header_size){
  phdr = (Elf32_Phdr*)(malloc(sizeof(Elf32_Phdr)));
  lseek(fd,ehdr->e_phoff + i*programm_header_size,SEEK_SET);
  
  if (read(fd, phdr, sizeof(Elf32_Phdr)) != sizeof(Elf32_Phdr)) {
    printf("Error: Couldn't read program header\n");
    exit(1);
  }
}

// Check if offset seeking was successful
void check_offset( off_t new_position ){
  if ( new_position == -1 )
  {
    printf("Failed to seek offset\n");
    exit(1);
  }
}

void handle_page_fault(int signum, siginfo_t *sig, void* context) {
  void *fault_addr = sig->si_addr;
  page_faults++;

  // Iterate over segments to find which one covers this fault address
  for (int i = 0; i < ehdr->e_phnum; i++) {

    uintptr_t segment_start = (uintptr_t)segments[i]->p_vaddr;
    uintptr_t segment_end = segment_start + segments[i]->p_memsz;

    // printf("Checking segment %d: start %p, end %p\n", i, (void*)segment_start, (void*)segment_end);

    // Check if the fault address falls within this segment
    if ((uintptr_t)fault_addr >= segment_start && (uintptr_t)fault_addr < segment_end) {
      // printf("Fault address %p found in segment %d\n", fault_addr, i);

      // Align the fault address to page boundary for mmap
      void *page_start = (void *)((uintptr_t)fault_addr & ~(PAGE_SIZE - 1));

      // Attempt to allocate memory for this page
      void *mapped_page = mmap(page_start, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

      if (mapped_page == MAP_FAILED) {
          perror("mmap failed");
          exit(1);
      }

      page_allocations++;

      // Seek to the appropriate offset in the ELF file
      size_t offset_within_segment = (uintptr_t)page_start - segment_start;
      check_offset(lseek(fd, segments[i]->p_offset + offset_within_segment, SEEK_SET));

      // Read the data into the newly mapped memory page
      ssize_t bytes_read = read(fd, mapped_page, PAGE_SIZE);
      // printf("Size of segment %d is %zu bytes\n", i, segments[i]->p_memsz);
      // printf("Number of bytes read into page at %p: %zd\n", page_start, bytes_read);

      if (bytes_read < 0) {
          perror("Failed to read segment data");
          exit(1);
      }

      if (segments[i]->p_filesz < PAGE_SIZE) {
        int unused_bytes = PAGE_SIZE - segments[i]->p_filesz;
        internal_fragmentation += unused_bytes;
        // printf("Internal fragmentation for this page: %d bytes\n", unused_bytes);
      }

      break;
    }
  }
}


/*
 * Load and run the ELF executable file
*/

void load_and_run_elf(char** elf_file) {

  char* ELF_file_name = elf_file[1];
  
  unsigned short int programm_header_size = ehdr->e_phentsize;
  
  for(int i = 0;i<ehdr->e_phnum;i++){

    read_programm_header(i,programm_header_size);
    segments[ptr] = phdr;
    ptr++;
  }

  Elf32_Addr entry_pt = ehdr -> e_entry;

  if(entry_pt!=NULL){
    int (*_start)() = (int(*)())entry_pt;
    int result = _start();
    printf("--------------------------------------------\n");
    printf("User _start return value = %d\n", result);
    printf("--------------------------------------------\n");
    printf("Page Faults:%d\nPage Allocations:%d\nInternal Fragmentations [in Bytes]:%d\n",page_faults,page_allocations,internal_fragmentation);
    printf("--------------------------------------------\n");
  }else{
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
}

int main(int argc, char** argv) {

  setup_signal_handler();

  if(argc != 2) {
    printf("Usage: %s <ELF Executable> \nYou need to provide ELF File as an argument\n",argv[0]);
    exit(1);
  }else{
    ELF_file_name = argv[1];
  }

  if (access(ELF_file_name, F_OK) != 0) {
    printf("Error: File %s does not exist.\n", ELF_file_name);
    exit(1);
  }

  fd = open(ELF_file_name, O_RDONLY);
  if (fd < 0) {
 	printf("Error opening file\n");
 	exit(1);
  }

  read_elf_header();  
  load_and_run_elf(argv);
  loader_cleanup();

  if (close(fd) < 0) {
	printf("Error closing file\n");
	exit(1);
  }

  return 0;
}