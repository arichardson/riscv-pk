// See LICENSE for license details.

#ifndef _VM_H
#define _VM_H

#include "encoding.h"
#include <stdint.h>

#define MEGAPAGE_SIZE ((uintptr_t)(RISCV_PGSIZE << RISCV_PGLEVEL_BITS))
#if __riscv_xlen == 64
# define SATP_MODE_CHOICE INSERT_FIELD(0, SATP64_MODE, SATP_MODE_SV39)
# define VA_BITS 39
# define GIGAPAGE_SIZE (MEGAPAGE_SIZE << RISCV_PGLEVEL_BITS)
typedef uint64_t addr_t;
#else
# define SATP_MODE_CHOICE INSERT_FIELD(0, SATP32_MODE, SATP_MODE_SV32)
# define VA_BITS 32
typedef uint32_t addr_t;
#endif
typedef addr_t pte_t;

extern pte_t* root_page_table;

static inline void flush_tlb()
{
  asm volatile ("sfence.vma");
}

static inline pte_t pte_create(addr_t ppn, int type)
{
  return (ppn << PTE_PPN_SHIFT) | PTE_V | type;
}

static inline pte_t ptd_create(addr_t ppn)
{
  return pte_create(ppn, PTE_V);
}

#endif
