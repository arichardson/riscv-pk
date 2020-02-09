// See LICENSE for license details.

#include "pk.h"
#include "mmap.h"
#include "boot.h"
#include "elf.h"
#include "mtrap.h"
#include "frontend.h"
#include <stdbool.h>

elf_info current;
long disabled_hart_mask;

static void help()
{
  printk("Proxy kernel\n\n");
  printk("usage: pk [pk options] <user program> [program options]\n");
  printk("Options:\n");
  printk("  -h, --help            Print this help message\n");
  printk("  -p                    Disable on-demand program paging\n");
  printk("  -s                    Print cycles upon termination\n");

  shutdown(0);
}

static void suggest_help()
{
  printk("Try 'pk --help' for more information.\n");
  shutdown(1);
}

static void handle_option(const char* arg)
{
  if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
    help();
    return;
  }

  if (strcmp(arg, "-s") == 0) {  // print cycle count upon termination
    current.cycle0 = 1;
    return;
  }

  if (strcmp(arg, "-p") == 0) { // disable demand paging
    demand_paging = 0;
    return;
  }

  panic("unrecognized option: `%s'", arg);
  suggest_help();
}

#define MAX_ARGS 256
typedef union {
  uint64_t buf[MAX_ARGS];
  char* argv[MAX_ARGS];
} arg_buf;

static size_t parse_args(arg_buf* args)
{
  long r = frontend_syscall(SYS_getmainvars, va2pa(args), sizeof(*args), 0, 0, 0, 0, 0);
  if (r != 0)
    panic("args must not exceed %d bytes", (int)sizeof(arg_buf));

  kassert(r == 0);
  uint64_t* pk_argv = &args->buf[1];
  // pk_argv[0] is the proxy kernel itself.  skip it and any flags.
  size_t pk_argc = args->buf[0], arg = 1;
  for ( ; arg < pk_argc && *(char*)(uintptr_t)pk_argv[arg] == '-'; arg++)
    handle_option((const char*)(uintptr_t)pk_argv[arg]);

  for (size_t i = 0; arg + i < pk_argc; i++)
    args->argv[i] = (char*)(uintptr_t)pk_argv[arg + i];
  return pk_argc - arg;
}

static void init_tf(trapframe_t* tf, long pc, void* sp)
{
  memset(tf, 0, sizeof(*tf));
  tf->status = (read_csr(sstatus) &~ SSTATUS_SPP &~ SSTATUS_SIE) | SSTATUS_SPIE;
  tf->gpr[2] = (uintptr_t)sp;
#if __has_feature(capabilities)
  void *pcc;
  tf->ddc = (uintptr_t)__builtin_cheri_global_data_get();
  pcc = __builtin_cheri_program_counter_get();
  pcc = __builtin_cheri_address_set(pcc, pc);
  pcc = __builtin_cheri_flags_set(pcc, 0);
  tf->epc = (uintptr_t)pcc;
#else
  tf->epc = pc;
#endif
}

static void run_loaded_program(size_t argc, char** argv, uintptr_t kstack_top)
{
  // copy phdrs to user stack
  void* stack_top = (void*)((uintptr_t)current.stack_top - current.phdr_size);
  memcpy(stack_top, current.phdr, current.phdr_size);
  current.phdr = stack_top;

  // copy argv to user stack
  for (size_t i = 0; i < argc; i++) {
    size_t len = strlen((char*)(uintptr_t)argv[i])+1;
    stack_top -= len;
    memcpy((void*)stack_top, (void*)(uintptr_t)argv[i], len);
    argv[i] = (void*)stack_top;
  }

  // copy envp to user stack
  const char* envp[] = {
    // environment goes here
  };
  size_t envc = sizeof(envp) / sizeof(envp[0]);
  for (size_t i = 0; i < envc; i++) {
    size_t len = strlen(envp[i]) + 1;
    stack_top -= len;
    memcpy((void*)stack_top, envp[i], len);
    envp[i] = (void*)stack_top;
  }

  // align stack
#define STACK_ALIGNMENT (sizeof(void*) < 16 ? 16 : sizeof(void*))
#if __has_builtin(__builtin_align_down)
#define ALIGN_STACK(sp) (__builtin_align_down(sp, STACK_ALIGNMENT))
#else
#define ALIGN_STACK(sp) ((uintptr_t)sp & -STACK_ALIGNMENT)
#endif

  stack_top = ALIGN_STACK(stack_top);

  struct {
    long key;
    long value;
  } aux[] = {
    {AT_ENTRY, current.entry},
    {AT_PHNUM, current.phnum},
    {AT_PHENT, current.phent},
    {AT_PHDR, (__cheri_addr addr_t)current.phdr},
    {AT_PAGESZ, RISCV_PGSIZE},
    {AT_SECURE, 0},
    {AT_RANDOM, (__cheri_addr addr_t)stack_top},
    {AT_NULL, 0}
  };

  // place argc, argv, envp, auxp on stack
  #define PUSH_ARG(type, value) do { \
    *((type*)ptr_to_ddccap((uintptr_t)(sp))) = (type)value; \
    sp += sizeof(type); \
  } while (0)

  #define STACK_INIT(type) do { \
    unsigned naux = sizeof(aux)/sizeof(aux[0]); \
    stack_top -= (1 + argc + 1 + envc + 1 + 2*naux) * sizeof(type); \
    stack_top = ALIGN_STACK(stack_top); \
    uintptr_t sp = (uintptr_t)stack_top; \
    PUSH_ARG(type, argc); \
    for (unsigned i = 0; i < argc; i++) \
      PUSH_ARG(type, argv[i]); \
    PUSH_ARG(type, 0); /* argv[argc] = NULL */ \
    for (unsigned i = 0; i < envc; i++) \
      PUSH_ARG(type, envp[i]); \
    PUSH_ARG(type, 0); /* envp[envc] = NULL */ \
    for (unsigned i = 0; i < naux; i++) { \
      PUSH_ARG(type, aux[i].key); \
      PUSH_ARG(type, aux[i].value); \
    } \
  } while (0)

  STACK_INIT(uintptr_t);

  if (current.cycle0) { // start timer if so requested
    current.time0 = rdtime64();
    current.cycle0 = rdcycle64();
    current.instret0 = rdinstret64();
  }

  trapframe_t tf;
  init_tf(&tf, current.entry, stack_top);
  asm volatile ("fence.i" ::: "memory");
  write_csr(sscratch, (addr_t)kstack_top);
#if __has_feature(capabilities)
  write_scr(sscratchc, kstack_top);
#endif
  start_user(&tf);
}

static void rest_of_boot_loader(uintptr_t kstack_top)
{
  arg_buf args;
  size_t argc = parse_args(&args);
  if (!argc)
    panic("tell me what ELF to load!");

  // load program named by argv[0]
  long phdrs[128];
  current.phdr = phdrs;
  current.phdr_size = sizeof(phdrs);
  load_elf(args.argv[0], &current);

  run_loaded_program(argc, args.argv, kstack_top);
}

void boot_loader(uintptr_t dtb)
{
  extern char trap_entry;
  write_csr(stvec, (addr_t)&trap_entry);
  write_csr(sscratch, 0);
  write_csr(sie, 0);
  set_csr(sstatus, SSTATUS_SUM | SSTATUS_FS | SSTATUS_VS);

  file_init();
  enter_supervisor_mode(rest_of_boot_loader, pk_vm_init(), 0);
}

void boot_other_hart(uintptr_t dtb)
{
  // stall all harts besides hart 0
  while (1)
    wfi();
}
