	.file 1 "disasm-optim.c"
	.file 2 "/opt/nec/ve/ncc/S001/include/stdc-predef.h"
	.file 3 "disasm-optim.h"
# ============ Begin  foo ============
	.text
	.balign 16
.L1.0:
# line 20
	.loc	3 20 0
	.globl	foo
	.type	foo,@function
foo:
	.cfi_startproc
	st	%fp,0x0(,%sp)
	.cfi_def_cfa_offset	0
	.cfi_offset	9,0
	st	%lr,0x8(,%sp)
	st	%got,0x18(,%sp)
	st	%plt,0x20(,%sp)
	or	%fp,0,%sp
	.cfi_def_cfa_register	9
	st	%s18,48(,%fp)
	st	%s19,56(,%fp)
	st	%s20,64(,%fp)
	st	%s21,72(,%fp)
	st	%s22,80(,%fp)
	st	%s23,88(,%fp)
	st	%s24,96(,%fp)
	st	%s25,104(,%fp)
	st	%s26,112(,%fp)
	st	%s27,120(,%fp)
	st	%s28,128(,%fp)
	st	%s29,136(,%fp)
	st	%s30,144(,%fp)
	st	%s31,152(,%fp)
	st	%s32,160(,%fp)
	st	%s33,168(,%fp)
	lea	%s13,.L.1.2auto_size&0xffffffff
	and	%s13,%s13,(32)0
	lea.sl	%sp,.L.1.2auto_size>>32(%fp,%s13)
	brge.l.t	%sp,%sl,.L1.EoP
	ld	%s61,0x18(,%tp)
	or	%s62,0,%s0
	lea	%s63,0x13b
	shm.l	%s63,0x0(%s61)
	shm.l	%sl,0x8(%s61)
	shm.l	%sp,0x10(%s61)
	monc
	or	%s0,0,%s62
.L1.EoP:
# End of prologue codes
# line 21
	# disasm-optim.h:21
	.loc	3 21 0
	brgt.w	0,%s0,.L1.2
	br.l	.L1.1
.L1.1:
# line 23
	.loc	3 23 0
	breq.w	0,%s0,.L1.4
	br.l	.L1.3
.L1.3:
# line 25
	.loc	3 25 0
	lea	%s63,10
	adds.w.sx	%s62,%s0,%s63
	st	%s62,-8(,%fp)	# spill
	br.l	.L1.5
.L1.4:
# line 24
	.loc	3 24 0
	or	%s63,1,(0)1
	st	%s63,-8(,%fp)	# spill
	br.l	.L1.5
.L1.2:
# line 22
	.loc	3 22 0
	sla.w.sx	%s63,%s0,1
	st	%s63,-8(,%fp)	# spill
	br.l	.L1.5
.L1.5:
# line 24
	.loc	3 24 0
	ld	%s0,-8(,%fp)	# restore
# Start of epilogue codes
	or	%sp,0,%fp
	.cfi_def_cfa	11,8
	ld	%got,0x18(,%sp)
	ld	%plt,0x20(,%sp)
	ld	%lr,0x8(,%sp)
	ld	%fp,0x0(,%sp)
	b.l	(,%lr)
	.cfi_endproc
	.set	.L.1.2auto_size,	0xfffffffffffffee0	# 288 Bytes
	.size	foo,	.-foo
# ============ End  foo ============
# ============ Begin  main ============
	.balign 16
.L2.0:
# line 24
	.loc	1 24 0
	.globl	main
	.type	main,@function
main:
	.cfi_startproc
	st	%fp,0x0(,%sp)
	.cfi_def_cfa_offset	0
	.cfi_offset	9,0
	st	%lr,0x8(,%sp)
	st	%got,0x18(,%sp)
	st	%plt,0x20(,%sp)
	or	%fp,0,%sp
	.cfi_def_cfa_register	9
	st	%s18,48(,%fp)
	st	%s19,56(,%fp)
	st	%s20,64(,%fp)
	st	%s21,72(,%fp)
	st	%s22,80(,%fp)
	st	%s23,88(,%fp)
	st	%s24,96(,%fp)
	st	%s25,104(,%fp)
	st	%s26,112(,%fp)
	st	%s27,120(,%fp)
	st	%s28,128(,%fp)
	st	%s29,136(,%fp)
	st	%s30,144(,%fp)
	st	%s31,152(,%fp)
	st	%s32,160(,%fp)
	st	%s33,168(,%fp)
	lea	%s13,.L.2.2auto_size&0xffffffff
	and	%s13,%s13,(32)0
	lea.sl	%sp,.L.2.2auto_size>>32(%fp,%s13)
	brge.l.t	%sp,%sl,.L2.EoP
	ld	%s61,0x18(,%tp)
	or	%s62,0,%s0
	lea	%s63,0x13b
	shm.l	%s63,0x0(%s61)
	shm.l	%sl,0x8(%s61)
	shm.l	%sp,0x10(%s61)
	monc
	or	%s0,0,%s62
.L2.EoP:
# End of prologue codes
# line 25
	.loc	1 25 0
	lea	%s63,y@LO
	and	%s63,%s63,(32)0
	lea.sl	%s63,y@HI(,%s63)
	ldl.sx	%s62,0(0,%s63)
	or	%s0,0,%s62
	lea	%s12,foo@LO
	and	%s12,%s12,(32)0
	lea.sl	%s12,foo@HI(,%s12)
	bsic	%lr,(,%s12)		# foo
	st	%s0,-8(,%fp)	# spill
	br.l	.L2.1
.L2.1:
	lea	%s63,x@LO
	and	%s63,%s63,(32)0
	lea.sl	%s63,x@HI(,%s63)
	ld	%s62,-8(,%fp)	# restore
	stl	%s62,0(0,%s63)
# line 26
	.loc	1 26 0
	or	%s61,0,(0)1
	or	%s0,0,%s61
# Start of epilogue codes
	or	%sp,0,%fp
	.cfi_def_cfa	11,8
	ld	%got,0x18(,%sp)
	ld	%plt,0x20(,%sp)
	ld	%lr,0x8(,%sp)
	ld	%fp,0x0(,%sp)
	b.l	(,%lr)
	.cfi_endproc
	.set	.L.2.2auto_size,	0xfffffffffffffe30	# 464 Bytes
	.size	main,	.-main
# ============ End  main ============
.comm y,4,4
.comm x,4,4
