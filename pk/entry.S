// See LICENSE for license details.

#include "encoding.h"
#include "bits.h"

  .macro save_tf
  # save gprs
#if __has_feature(capabilities)
  csc  c1,1*REGBYTES(c2)
  csc  c3,3*REGBYTES(c2)
  csc  c4,4*REGBYTES(c2)
  csc  c5,5*REGBYTES(c2)
  csc  c6,6*REGBYTES(c2)
  csc  c7,7*REGBYTES(c2)
  csc  c8,8*REGBYTES(c2)
  csc  c9,9*REGBYTES(c2)
  csc  c10,10*REGBYTES(c2)
  csc  c11,11*REGBYTES(c2)
  csc  c12,12*REGBYTES(c2)
  csc  c13,13*REGBYTES(c2)
  csc  c14,14*REGBYTES(c2)
  csc  c15,15*REGBYTES(c2)
  csc  c16,16*REGBYTES(c2)
  csc  c17,17*REGBYTES(c2)
  csc  c18,18*REGBYTES(c2)
  csc  c19,19*REGBYTES(c2)
  csc  c20,20*REGBYTES(c2)
  csc  c21,21*REGBYTES(c2)
  csc  c22,22*REGBYTES(c2)
  csc  c23,23*REGBYTES(c2)
  csc  c24,24*REGBYTES(c2)
  csc  c25,25*REGBYTES(c2)
  csc  c26,26*REGBYTES(c2)
  csc  c27,27*REGBYTES(c2)
  csc  c28,28*REGBYTES(c2)
  csc  c29,29*REGBYTES(c2)
  csc  c30,30*REGBYTES(c2)
  csc  c31,31*REGBYTES(c2)

  # get sr, epc, badvaddr, cause
  cspecialr ct0,sscratchc
  csrr   s0,sstatus
  cspecialr ct1,sepcc
  csrr   t2,stval
  csrr   t3,scause
  csc  ct0,2*REGBYTES(c2)
  csc  cs0,32*REGBYTES(c2)
  csc  ct1,33*REGBYTES(c2)
  csc  ct2,34*REGBYTES(c2)
  csc  ct3,35*REGBYTES(c2)

  # get faulting insn, if it wasn't a fetch-related trap
  li x5,-1
  csc  c5,36*REGBYTES(c2)

  # get ddc
  cspecialr ct0,ddc
  csc  ct0,36*REGBYTES(c2)
1:
  .endm

  .text
  .align 2
  .global  trap_entry
  .type trap_entry, @function
trap_entry:
  cspecialrw csp, sscratchc, csp
  bnez sp, 1f
  cspecialr csp, sscratchc
1:cincoffset csp,csp,-656
  save_tf
  cmove  ca0,csp
  cllc  ct1, handle_trap
  cjalr cra, ct1

  cmove ca0,csp
  # don't restore sscratch if trap came from kernel
  andi s0,s0,SSTATUS_SPP
  bnez s0,start_user
  cincoffset csp,csp,656
  cspecialw sscratchc,csp

  .type start_user, @function
  .globl start_user
start_user:
  LOAD t0, 32*REGBYTES(ca0)
  clc ct1, 33*REGBYTES(ca0)
  csrw sstatus, t0
  cspecialw sepcc, ct1

  # restore ddc
  clc  ct0,36*REGBYTES(ca0)
  cspecialw ddc,ct0

  # restore c registers
  clc  c1,1*REGBYTES(ca0)
  clc  c2,2*REGBYTES(ca0)
  clc  c3,3*REGBYTES(ca0)
  clc  c4,4*REGBYTES(ca0)
  clc  c5,5*REGBYTES(ca0)
  clc  c6,6*REGBYTES(ca0)
  clc  c7,7*REGBYTES(ca0)
  clc  c8,8*REGBYTES(ca0)
  clc  c9,9*REGBYTES(ca0)
  clc  c11,11*REGBYTES(ca0)
  clc  c12,12*REGBYTES(ca0)
  clc  c13,13*REGBYTES(ca0)
  clc  c14,14*REGBYTES(ca0)
  clc  c15,15*REGBYTES(ca0)
  clc  c16,16*REGBYTES(ca0)
  clc  c17,17*REGBYTES(ca0)
  clc  c18,18*REGBYTES(ca0)
  clc  c19,19*REGBYTES(ca0)
  clc  c20,20*REGBYTES(ca0)
  clc  c21,21*REGBYTES(ca0)
  clc  c22,22*REGBYTES(ca0)
  clc  c23,23*REGBYTES(ca0)
  clc  c24,24*REGBYTES(ca0)
  clc  c25,25*REGBYTES(ca0)
  clc  c26,26*REGBYTES(ca0)
  clc  c27,27*REGBYTES(ca0)
  clc  c28,28*REGBYTES(ca0)
  clc  c29,29*REGBYTES(ca0)
  clc  c30,30*REGBYTES(ca0)
  clc  c31,31*REGBYTES(ca0)
  # restore a0 last
  clc  c10,10*REGBYTES(ca0)
#else
  STORE  x1,1*REGBYTES(x2)
  STORE  x3,3*REGBYTES(x2)
  STORE  x4,4*REGBYTES(x2)
  STORE  x5,5*REGBYTES(x2)
  STORE  x6,6*REGBYTES(x2)
  STORE  x7,7*REGBYTES(x2)
  STORE  x8,8*REGBYTES(x2)
  STORE  x9,9*REGBYTES(x2)
  STORE  x10,10*REGBYTES(x2)
  STORE  x11,11*REGBYTES(x2)
  STORE  x12,12*REGBYTES(x2)
  STORE  x13,13*REGBYTES(x2)
  STORE  x14,14*REGBYTES(x2)
  STORE  x15,15*REGBYTES(x2)
  STORE  x16,16*REGBYTES(x2)
  STORE  x17,17*REGBYTES(x2)
  STORE  x18,18*REGBYTES(x2)
  STORE  x19,19*REGBYTES(x2)
  STORE  x20,20*REGBYTES(x2)
  STORE  x21,21*REGBYTES(x2)
  STORE  x22,22*REGBYTES(x2)
  STORE  x23,23*REGBYTES(x2)
  STORE  x24,24*REGBYTES(x2)
  STORE  x25,25*REGBYTES(x2)
  STORE  x26,26*REGBYTES(x2)
  STORE  x27,27*REGBYTES(x2)
  STORE  x28,28*REGBYTES(x2)
  STORE  x29,29*REGBYTES(x2)
  STORE  x30,30*REGBYTES(x2)
  STORE  x31,31*REGBYTES(x2)

  # get sr, epc, badvaddr, cause
  csrrw  t0,sscratch,x0
  csrr   s0,sstatus
  csrr   t1,sepc
  csrr   t2,stval
  csrr   t3,scause
  STORE  t0,2*REGBYTES(x2)
  STORE  s0,32*REGBYTES(x2)
  STORE  t1,33*REGBYTES(x2)
  STORE  t2,34*REGBYTES(x2)
  STORE  t3,35*REGBYTES(x2)

  # get faulting insn, if it wasn't a fetch-related trap
  li x5,-1
  STORE x5,36*REGBYTES(x2)
1:
  .endm

  .text
  .align 2
  .global  trap_entry
trap_entry:
  csrrw sp, sscratch, sp
  bnez sp, 1f
  csrr sp, sscratch
1:addi sp,sp,-320
  save_tf
  move  a0,sp
  jal handle_trap

  mv a0,sp
  # don't restore sscratch if trap came from kernel
  andi s0,s0,SSTATUS_SPP
  bnez s0,start_user
  addi sp,sp,320
  csrw sscratch,sp
  
  .globl start_user
start_user:
  LOAD t0, 32*REGBYTES(a0)
  LOAD t1, 33*REGBYTES(a0)
  csrw sstatus, t0
  csrw sepc, t1

  # restore x registers
  LOAD  x1,1*REGBYTES(a0)
  LOAD  x2,2*REGBYTES(a0)
  LOAD  x3,3*REGBYTES(a0)
  LOAD  x4,4*REGBYTES(a0)
  LOAD  x5,5*REGBYTES(a0)
  LOAD  x6,6*REGBYTES(a0)
  LOAD  x7,7*REGBYTES(a0)
  LOAD  x8,8*REGBYTES(a0)
  LOAD  x9,9*REGBYTES(a0)
  LOAD  x11,11*REGBYTES(a0)
  LOAD  x12,12*REGBYTES(a0)
  LOAD  x13,13*REGBYTES(a0)
  LOAD  x14,14*REGBYTES(a0)
  LOAD  x15,15*REGBYTES(a0)
  LOAD  x16,16*REGBYTES(a0)
  LOAD  x17,17*REGBYTES(a0)
  LOAD  x18,18*REGBYTES(a0)
  LOAD  x19,19*REGBYTES(a0)
  LOAD  x20,20*REGBYTES(a0)
  LOAD  x21,21*REGBYTES(a0)
  LOAD  x22,22*REGBYTES(a0)
  LOAD  x23,23*REGBYTES(a0)
  LOAD  x24,24*REGBYTES(a0)
  LOAD  x25,25*REGBYTES(a0)
  LOAD  x26,26*REGBYTES(a0)
  LOAD  x27,27*REGBYTES(a0)
  LOAD  x28,28*REGBYTES(a0)
  LOAD  x29,29*REGBYTES(a0)
  LOAD  x30,30*REGBYTES(a0)
  LOAD  x31,31*REGBYTES(a0)
  # restore a0 last
  LOAD  x10,10*REGBYTES(a0)
#endif

  # gtfo
  sret
.size trap_entry, . - trap_entry
