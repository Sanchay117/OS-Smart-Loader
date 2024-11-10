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

// Check if offset seeking was successful
void check_offset( off_t new_position ){
  if ( new_position == -1 )
  {
    printf("Failed to seek offset\n");
    exit(1);
  }
}

void handle_page_fault(int signum,siginfo_t *sig,void* context){
  printf("PAGE FAULT / SEG FAULT\n");
  // no_of_faults++;
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if ((sig -> si_addr) >= (segments[i]->p_vaddr) && (sig->si_addr) < segments[i]->p_vaddr + segments[i]->p_memsz) {
      printf("Fault address is : %p\n", sig->si_addr);

      // Attempt to allocate memory using mmap
      void* virtual_mem = mmap(sig->si_addr, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

      if (virtual_mem == MAP_FAILED) {
        // mmap failed
        printf("mmap failed\n");
        exit(1);
      }
      check_offset(lseek(fd, 0, SEEK_SET) );
      check_offset(lseek(fd, segments[i]->p_offset, SEEK_SET));
      ssize_t bytes_read = read(fd, virtual_mem, PAGE_SIZE);

      printf("size of phdr segment is %d\n", phdr[i].p_memsz);
      printf("Number of bytes read: %d\n", bytes_read);

      if (bytes_read < 0) {
        printf("Less than 0 bytes read\n");
        exit(1);
      }
      // add_fragmentation(bytes_read);
      // pages++;
      break;
    }
  }
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
    segments[ptr] = phdr;
    ptr++;
    
    // not freeing this in loader_cleanup as pointer referencing a new address for every programm header
    free(phdr);
  }

  //typecasting the entry point of the start function
  Elf32_Addr entry_pt = ehdr -> e_entry;

  if(entry_pt!=NULL){
    int (*_start)() = (int(*)())entry_pt;
    int result = _start();
    printf("--------------------------------------------\n");
    printf("User _start return value = %d\n", result);
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