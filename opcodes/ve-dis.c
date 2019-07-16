/* Disassembler for NEC VE processor.

   Copyright (C) 2014-2016 NEC Corporation.

   This program is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, U\SA.
*/

#include "sysdep.h"
#include <stdio.h>
#include "dis-asm.h"
#include "opcode/ve.h"

static inline int
ve_find_opc_index(ve_instr *inst)
{
  int i, idx = -1;
  unsigned int flag = 0;
  unsigned char op = inst->gen.upper.w1.op;

  if (inst->gen.upper.w1.x & 0x80)
    {
      flag |= CX_ON;
    }
  if (op == O_FENCE && inst->gen.upper.w1.y)
    {
      flag |= FENCE_C;
    }
  if (op == O_LHM || op == O_SHM)
    {
      flag |= inst->rr.y.bity.ry << DS_SHFT;
    }
  if (op == O_CMOV && inst->rr.w.bitw.cfw)
    {
      flag |= inst->rr.w.bitw.cfw << CF_SHFT;
    }
  if (op == O_FIX || op == O_FIXX)
    {
      flag |= inst->rr.z.bitz.rz << RD_SHFT;
    }
  if (op == O_VFIX || op == O_VFIXX)
    {
      flag |= (inst->rv.vz << RD_SHFT) & RD_MASK;
    }
  if (op == O_BCR || op == O_BC || op == O_BCS || op == O_BCF)
    {
      flag |= inst->cf.x.bitx.cf << CF_SHFT;
      flag |= inst->cf.x.bitx.bpf << BP_SHFT;
      if (op == O_BCR && (inst->gen.upper.w1.x & 0x40))
        {
          flag |= CX2_ON;
        }
    }
  if (op == O_VLD || op == O_VLDU || op == O_VLDL || op == O_VST ||
      op == O_VSTU || op == O_VSTL || op == O_VGT || op == O_VGTU ||
      op == O_VGTL || op == O_VSC || op == O_VSCU || op == O_VSCL ||
      op == O_VLD2D || op == O_VLDU2D || op == O_VLDL2D ||
      op == O_VST2D || op == O_VSTU2D || op == O_VSTL2D ||
      op == O_PFCHV)
    {
      if (inst->rvm.x.bitx.vc)
        {
          flag |= VC_ON;
        }
    }
  if (op == O_VFIX || op == O_VRSQRT || op == O_VCMS || op == O_VCMX ||
      op == O_VFCM || op == O_VMAXS || op == O_VMAXX || op == O_VFMAX ||
      op == O_VFLT)
    {
      if (inst->rv.x.bitx.cs2)
        {
          flag |= CM_ON;
        }
    }
  if (op == O_VMAXS || op == O_VMAXX || op == O_VFMAX)
    {
      if (inst->rv.x.bitx.cs)
        {
          flag |= CT_ON;
        }
    }
  if (op == O_VFMK || op == O_VFMS || op == O_VFMF)
    {
      flag |= inst->rv.vy << CF_SHFT;
    }

  /* Because these instructions have displacement fields, avoid them. */
  if (op != O_LDS && op != O_LDU && op != O_LDL && op != O_LD2B &&
      op != O_LD1B && op != O_LEA && op != O_BSIC && op != O_DLDS &&
      op != O_DLDU && op != O_DLDL && op != O_PFCH && op != O_STS &&
      op != O_STU && op != O_STL && op != O_ST2B && op != O_ST1B &&
      op != O_BCR && op != O_BC && op != O_BCS && op != O_BCF &&
      op != O_LHM && op != O_SHM && op != O_TS1AM && op != O_TS2AM &&
      op != O_TS3AM && op != O_ATMAM && op != O_CAS)
    {
      if (inst->gen.lower.w3.vw & 0x80)
        {
          flag |= CW_ON;
        }
      if (inst->gen.lower.w3.vw & 0x40)
        {
          flag |= CW2_ON;
        }
    }

  if (op == O_VBRD || op == O_VADD || op == O_VADS || op == O_VSUB ||
      op == O_VSBS || op == O_VMPY || op == O_VMPS || op == O_VDIV ||
      op == O_VDVS || op == O_VCMP || op == O_VCPS || op == O_VCMS ||
      op == O_VAND || op == O_VOR || op == O_VXOR || op == O_VEQV ||
      op == O_VLDZ || op == O_VPCNT || op == O_VBRV || op == O_VSEQ ||
      op == O_VSLL || op == O_VSRL || op == O_VSLA || op == O_VSRA ||
      op == O_VFAD || op == O_VFSB || op == O_VFMP || op == O_VFCP ||
      op == O_VFCM || op == O_VFMAD || op == O_VFMSB || op == O_VFNMAD ||
      op == O_VFNMSB || op == O_VRCP || op == O_VRSQRT || op == O_VFIX ||
      op == O_VFLT || op == O_VMAXS || op == O_VFMF || op == O_VSUMS)
    {
      if (inst->rv.x.bitx.cx2)
        {
          flag |= CX2_ON;
        }
    }

  for (i = 0; i <= ve_num_opcodes; i++)
    {
      if (ve_opcodes[i].opcode == inst->gen.upper.w1.op &&
          ve_opcodes[i].flag == flag)
        {
          idx = i;
          break;
        }
    }
  return idx;
}

static void
print_ve_scalar_reg(disassemble_info *info, unsigned char field)
{
  (*info->fprintf_func)(info->stream, "%%s%d", (field & 0x7f));
}

static void
print_ve_vector_reg(disassemble_info *info, unsigned char field)
{
  (*info->fprintf_func)(info->stream, "%%v%d", (field & 0x7f));
}

static void
print_ve_vmask_reg(disassemble_info *info, unsigned char field)
{
  if ((field & 0x0f) != 0)
    {
      /* vm0 means no mask operation. */
      (*info->fprintf_func)(info->stream, "%%vm%d", (field & 0x0f));
    }
}

/*
static void
print_ve_reg(disassemble_info *info, unsigned short flag,
                 unsigned char field,
                 unsigned short dflag ATTRIBUTE_UNUSED,
                 int dfield ATTRIBUTE_UNUSED)
{
  if ((flag & TVREG) == TVREG)
    {
      (*info->fprintf_func)(info->stream, "%%v%d", (field & 0x7f));
    }
  else if ((flag & TSREG) == TSREG)
    {
      (*info->fprintf_func)(info->stream, "%%s%d", (field & 0x7f));
    }
  else if ((flag & TVMREG) == TVMREG)
    {
      (*info->fprintf_func)(info->stream, "%%vm%d", (field & 0x0f));
    }
}
*/

static void
print_ve_literal(disassemble_info *info, unsigned short flag,
                     unsigned char field)
{
  if ((flag & TLIT_MASK) == TLI127)
    {
      (*info->fprintf_func)(info->stream, "%d", (field & 0x7f));
    }
  else if ((flag & TLIT_MASK) == TLIS63)
    {
      int val;

      if (field & 0x40)
        {
          val = (int)((unsigned int)field | 0xffffff80);
        }
      else
        {
          val = (field & 0x7f);
        }
      (*info->fprintf_func)(info->stream, "%d", val);
    }
  else if ((flag & TLIT_MASK) == TLM0M1)
    {
      (*info->fprintf_func)(info->stream, "(%d)%d", (field & 0x3f),
                            (field & 0x40)? 0 : 1);
    }
  else
    {
      (*info->fprintf_func)(info->stream, "%d", (field & 0x7f));
    }
}

static void
print_ve_opc_field(disassemble_info *info, unsigned char opcode,
                       unsigned short flag, unsigned char field,
                       unsigned short dflag ATTRIBUTE_UNUSED, int dfield)
{
  if (((flag & TLITER) == TLITER || (flag & TSOFT) == TSOFT) && 
      (field & 0x80) == 0)
    {
      print_ve_literal(info, flag, field);
    }
  else if ((flag & TREG) == TREG)
    {
      print_ve_scalar_reg(info, field);
    }
  else if ((flag & TDISPL) == TDISPL)
    {
      if (dfield >= 0)
        {
          (*info->fprintf_func)(info->stream, "0x%x", dfield);
        }
      else
        {
          (*info->fprintf_func)(info->stream, "-0x%x", abs(dfield));
        }
    }
  else if ((flag & TSOFT) == TSOFT)
    {
      (*info->fprintf_func)(info->stream, "%d", field & 0x7f);
    }
  else
    {
      fprintf(stderr, "ERROR: unhandled flag %04x for opcode %d.\n",
              flag, opcode);
#if 0
      abort();
#else
      (*info->fprintf_func)(info->stream, "(bad)");
#endif
    }
}

static void
print_ve_vopc_field(disassemble_info *info, unsigned char opcode,
                        unsigned short flag, unsigned char field,
                        bfd_boolean is_scalar_op)
{
  if (is_scalar_op)
    {
      if (((flag & TLITER) == TLITER || (flag & TSOFT) == TSOFT) &&
           (field & 0x80) == 0)
        {
          print_ve_literal(info, flag, field);
        }
      else if ((flag & TREG) == TREG)
        {
          /* it should be scalar register. */
          print_ve_scalar_reg(info, field);
        }
      else if ((flag & TSOFT) == TSOFT)
        {
          (*info->fprintf_func)(info->stream, "%d", field & 0x7f);
        }
      else
        {
          fprintf(stderr,
                  "ERROR: unhandled flag %04x for opcode %d (is_scalar).\n",
                  flag, opcode);
          abort();
        }
    }
  else
    {
      /* it should be vector or vector mask register. */
      if ((flag & TVMREG) == TVMREG)
        {
          print_ve_vmask_reg(info, field);
        }
      else if ((flag & TVIXREG) == TVIXREG && field == 0xff) 
        {
          (*info->fprintf_func)(info->stream, "%%vix");
        }
      else if ((flag & TVREG) == TVREG)
        {
          print_ve_vector_reg(info, field);
        }
      else
        {
          fprintf(stderr, "ERROR: unhandled flag %04x for opcode %d.\n",
                  flag, opcode);
          abort();
        }
    }
}

static void
print_scalar_operands(disassemble_info *info, ve_instr *ins,
                      ve_opcode *op)
{
  int comma = 0;

  switch (VE_OA_FMT(op->format))
    {
    case FM_XYZWM:
      /* normal format X,Y,Z,W,M */
      if (op->field.x)
        {
          if (op->opcode == O_LSV || op->opcode == O_LVM)
            {
              print_ve_vopc_field(info, op->opcode, op->field.x,
                                      ins->rr.vx, FALSE);
            }
          else
            {
              print_ve_opc_field(info, op->opcode, op->field.x,
                                     ins->gen.upper.w1.x, 0, ins->gen.lower.d);
            }
          comma = 1;
        }
      if (op->field.y)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          if (op->opcode == O_LVS)
            {
              print_ve_vopc_field(info, op->opcode, op->field.y,
                                      ins->rr.vx, FALSE);
            }
          else
            {
              print_ve_opc_field(info, op->opcode, op->field.y,
                                     ins->gen.upper.w1.y, 0, ins->gen.lower.d);
            }
          comma = 1;
        }
      if (op->field.z)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          print_ve_opc_field(info, op->opcode, op->field.z,
                                 ins->gen.upper.w1.z, op->field.d,
                                 ins->gen.lower.d);
        }
      /* scalar instructions do not have W and M operands. */
      break;
    case FM_XZY:
      /* format X,Z,Y */
      if (op->field.x)
        {
          print_ve_opc_field(info, op->opcode, op->field.x,
                                 ins->gen.upper.w1.x, 0, ins->gen.lower.d);
          comma = 1;
        }
      if (op->field.z)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
              comma = 0;
            }
          if (op->opcode == O_SVM)
            {
              print_ve_vopc_field(info, op->opcode, op->field.z,
                                      ins->rr.vz, FALSE);
            }
          else
            {
              print_ve_opc_field(info, op->opcode, op->field.z, 
                                     ins->gen.upper.w1.z, op->field.d,
                                     ins->gen.lower.d);
            }
          comma = 1;
        }
      if (op->field.y)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
              comma = 0;
            }
          print_ve_opc_field(info, op->opcode, op->field.y,
                                 ins->gen.upper.w1.y, 0, ins->gen.lower.d);
        }
      break;
    case FM_AS:
      /* format disp(,base) */
      if (op->opcode == O_BCR)
        {
          /* special case: format y, z, disp */
          if (op->field.y)
            {
              print_ve_opc_field(info, op->opcode, op->field.y,
                                     ins->gen.upper.w1.y, 0, ins->gen.lower.d);
              (*info->fprintf_func)(info->stream, ",");
            }
          if (op->field.z)
            {
              print_ve_opc_field(info, op->opcode, op->field.z,
                                     ins->gen.upper.w1.z, 0, ins->gen.lower.d);
              (*info->fprintf_func)(info->stream, ",");
            }
          if (op->field.d)
            {
              print_ve_opc_field(info, op->opcode, op->field.d,
                                     ins->gen.upper.w1.y, 0, ins->gen.lower.d);
            }
          break;
        }
      else if (op->opcode == O_LHM || op->opcode == O_SHM)
        {
          /* format: disp(base) */
          if (op->field.x)
            {
              print_ve_opc_field(info, op->opcode, op->field.x,
                                     ins->gen.upper.w1.x, 0, ins->gen.lower.d);
              (*info->fprintf_func)(info->stream, ",");
            }
          if (op->field.d)
            {
              print_ve_opc_field(info, op->opcode, op->field.d,
                                     ins->gen.upper.w1.y, 0, ins->gen.lower.d);
              (*info->fprintf_func)(info->stream, "(");
            }
          if (op->field.z)
            {
              print_ve_opc_field(info, op->opcode, op->field.z,
                                     ins->gen.upper.w1.z, 0, ins->gen.lower.d);
            }
          else
            {
              (*info->fprintf_func)(info->stream, "0");
            }
          if (op->field.d)
            {
              (*info->fprintf_func)(info->stream, ")");
            }
          break;
        }
      else if (op->opcode == O_TS1AM || op->opcode == O_TS1AM ||
               op->opcode == O_TS3AM || op->opcode == O_ATMAM ||
               op->opcode == O_CAS)
        {
          /* format: disp(base) */
          if (op->field.x)
            {
              print_ve_opc_field(info, op->opcode, op->field.x,
                                     ins->gen.upper.w1.x, 0, ins->gen.lower.d);
              (*info->fprintf_func)(info->stream, ",");
            }
          if (op->field.d)
            {
              print_ve_opc_field(info, op->opcode, op->field.d,
                                     ins->gen.upper.w1.y, 0, ins->gen.lower.d);
            }
          (*info->fprintf_func)(info->stream, "(");
          (*info->fprintf_func)(info->stream, ",");
          if (op->field.z)
            {
              print_ve_opc_field(info, op->opcode, op->field.z,
                                     ins->gen.upper.w1.z, 0, ins->gen.lower.d);
            }
          else
            {
              (*info->fprintf_func)(info->stream, "0");
            }
          (*info->fprintf_func)(info->stream, ")");

        if (op->field.y)
          {
              (*info->fprintf_func)(info->stream, ",");
              print_ve_opc_field(info, op->opcode, op->field.y,
                                     ins->gen.upper.w1.y, 0, ins->gen.lower.d);
          }
          break;
        }
    case FM_ASX:
      /* format disp(index,base) */
      if (op->field.x)
        {
          print_ve_opc_field(info, op->opcode, op->field.x,
                                 ins->gen.upper.w1.x, 0, ins->gen.lower.d);
          (*info->fprintf_func)(info->stream, ",");
        }
      if (op->field.y && (VE_OA_FMT(op->format) == FM_AS))
        {
          print_ve_opc_field(info, op->opcode, op->field.y,
                                 ins->gen.upper.w1.y, 0, ins->gen.lower.d);
          (*info->fprintf_func)(info->stream, ",");
        }
      if (op->field.d)
        {
          print_ve_opc_field(info, op->opcode, op->field.d,
                                 ins->gen.upper.w1.y, 0, ins->gen.lower.d);
        }
      (*info->fprintf_func)(info->stream, "(");
      if (op->field.y && (VE_OA_FMT(op->format) == FM_ASX))
        {
          print_ve_opc_field(info, op->opcode, op->field.y,
                                 ins->gen.upper.w1.y, 0, ins->gen.lower.d);
        }
      if (op->field.z)
        {
          (*info->fprintf_func)(info->stream, ",");
          print_ve_opc_field(info, op->opcode, op->field.z,
                                 ins->gen.upper.w1.z, 0, ins->gen.lower.d);
        }
      (*info->fprintf_func)(info->stream, ")");
      break;
    case FM_DX_ZY:
      /* format X,Z(Y) */
      if (op->field.x)
        {
          print_ve_opc_field(info, op->opcode, op->field.x,
                                 ins->gen.upper.w1.x, 0, ins->gen.lower.d);
          comma = 1;
        }
      if (op->field.z)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
              comma = 0;
            }
          print_ve_vopc_field(info, op->opcode, op->field.z,
                                  ins->rr.vx, FALSE);
        }
      (*info->fprintf_func)(info->stream, "(");
      if (op->field.y)
        {
          print_ve_opc_field(info, op->opcode, op->field.y,
                                 ins->gen.upper.w1.y, 0, ins->gen.lower.d);
        }
      (*info->fprintf_func)(info->stream, ")");
      break;
    case FM_DXY_Z:
      /* format X(Y),Z */
      if (op->field.x)
        {
          print_ve_vopc_field(info, op->opcode, op->field.x,
                                  ins->rr.vx, FALSE);
        }
      (*info->fprintf_func)(info->stream, "(");
      if (op->field.y)
        {
          print_ve_opc_field(info, op->opcode, op->field.y,
                                 ins->gen.upper.w1.y, 0, ins->gen.lower.d);
        }
      (*info->fprintf_func)(info->stream, ")");
      if (op->field.z)
        {
          (*info->fprintf_func)(info->stream, ",");
          print_ve_opc_field(info, op->opcode, op->field.z,
                                 ins->gen.upper.w1.z, 0, ins->gen.lower.d);
        }
      break;
    }
}

static void
print_vector_operands(disassemble_info *info, ve_instr *ins,
                      ve_opcode *op)
{
  int comma = 0;

  switch (VE_OA_FMT(op->format))
    {
    case FM_XYZM:
      /* format X,Y,Z,M */
      if (op->field.x)
        {
          print_ve_vopc_field(info, op->opcode, op->field.x,
                                  ins->gen.lower.w3.vx, FALSE);
          comma = 1;
        }
      if (op->field.y)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          if (ins->rv.x.bitx.cs ||
              op->opcode == O_VMV || op->opcode == O_VBRD ||
              op->opcode == O_VSLD || op->opcode == O_VSRD ||
              op->opcode == O_VSFA || op->opcode == O_VFIM ||
              op->opcode == O_VFIAM || op->opcode == O_VFISM ||
              op->opcode == O_VFIMA || op->opcode == O_VFIMS)
            {
              /* Cs is on. */
              print_ve_vopc_field(info, op->opcode, op->field.y,
                                      ins->gen.upper.w1.y, TRUE);
            }
          else if (op->opcode == O_VST || op->opcode == O_VSTU ||
                   op->opcode == O_VSTL || op->opcode == O_VST2D ||
                   op->opcode == O_VSTU2D || op->opcode == O_VSTL2D)
            {
              print_ve_vopc_field(info, op->opcode, op->field.y,
                                      ins->gen.upper.w1.y, TRUE);
            }
          else
            {
              print_ve_vopc_field(info, op->opcode, op->field.y,
                                      ins->gen.lower.w3.vy, FALSE);
            }

          comma = 1;
        }
      if (op->field.z)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          if (op->opcode == O_VST || op->opcode == O_VSTU ||
              op->opcode == O_VSTL || op->opcode == O_VST2D ||
              op->opcode == O_VSTU2D || op->opcode == O_VSTL2D)
            {
              print_ve_vopc_field(info, op->opcode, op->field.z,
                                      ins->gen.upper.w1.z, TRUE);
            }
          else if ((op->opcode == O_VDIV || op->opcode == O_VDVS ||
                    op->opcode == O_VDVX || op->opcode == O_VFDV) &&
                   (ins->gen.upper.w1.x & 0x10))
            {
              print_ve_vopc_field(info, op->opcode, op->field.z,
                                      ins->gen.upper.w1.y, TRUE);
            }
          else
            {
              print_ve_vopc_field(info, op->opcode, op->field.z,
                                      ins->gen.lower.w3.vz, FALSE);
            }
          comma = 1;
        }
      if (op->field.m)
        {
          if (comma && (ins->gen.upper.w1.x & 0x0f))
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          print_ve_vopc_field(info, op->opcode, op->field.m,
                                  ins->gen.upper.w1.x, FALSE);
        }
      break;
    case FM_XZYM:
      /* format X,Z,Y,M */
      if (op->field.x)
        {
          print_ve_vopc_field(info, op->opcode, op->field.x,
                                  ins->gen.lower.w3.vx, FALSE);
          comma = 1;
        }
      if (op->field.z)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          print_ve_vopc_field(info, op->opcode, op->field.z,
                                  ins->gen.lower.w3.vz, FALSE);
          comma = 1;
        }
      if (op->field.y)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          if (ins->rv.x.bitx.cs)
            {
              /* Cs is on. */
              print_ve_vopc_field(info, op->opcode, op->field.y,
                                      ins->gen.upper.w1.y, TRUE);
            }
          else
            {
              print_ve_vopc_field(info, op->opcode, op->field.y,
                                      ins->gen.lower.w3.vy, FALSE);
            }

          comma = 1;
        }
      if (op->field.m)
        {
          if (comma && (ins->gen.upper.w1.x & 0x0f))
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          print_ve_vopc_field(info, op->opcode, op->field.m,
                                  ins->gen.upper.w1.x, FALSE);
        }
      break;
    case FM_XYZWM:
    case FM_X_DYZ_WM:
      /* format X,Y,Z,W,M or X,(Y,Z),W,M */
      if (op->field.x)
        {
          if (op->opcode == O_PCVM || op->opcode == O_LZVM ||
              op->opcode == O_TOVM)
            {
              print_ve_vopc_field(info, op->opcode, op->field.x,
                                      ins->gen.upper.w1.x, TRUE);
            }
          else
            {
              print_ve_vopc_field(info, op->opcode, op->field.x,
                                      ins->gen.lower.w3.vx, FALSE);
            }
          comma = 1;
        }
      if (op->field.y)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          if (VE_OA_FMT(op->format) == FM_X_DYZ_WM)
            {
              (*info->fprintf_func)(info->stream, "(");
            }
          if (op->opcode == O_PCVM || op->opcode == O_LZVM ||
              op->opcode == O_TOVM)
            {
              print_ve_vopc_field(info, op->opcode, op->field.y,
                                      ins->rv.vy, FALSE);
          } else if (ins->rv.x.bitx.cs ||
              op->opcode == O_VBRD || op->opcode == O_VLD ||
              op->opcode == O_VLDU || op->opcode == O_VLDL ||
              op->opcode == O_VST || op->opcode == O_VSTU ||
              op->opcode == O_VSTL || op->opcode == O_PFCHV ||
              op->opcode == O_VLD2D || op->opcode == O_VLDU2D ||
              op->opcode == O_VLDL2D || op->opcode == O_VST2D ||
              op->opcode == O_VSTU2D || op->opcode == O_VSTL2D)
            {
              print_ve_vopc_field(info, op->opcode, op->field.y,
                                      ins->rv.y.y, TRUE);
            }
          else
            {
              print_ve_vopc_field(info, op->opcode, op->field.y,
                                      ins->rv.vy, FALSE);
            }
          comma = 1;
        }
      if (op->field.z)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          if (op->opcode == O_VLD || op->opcode == O_VLDU ||
              op->opcode == O_VLDL || op->opcode == O_VST ||
              op->opcode == O_VSTU || op->opcode == O_VSTL ||
              op->opcode == O_VLD2D || op->opcode == O_VLDU2D ||
              op->opcode == O_VLDL2D || op->opcode == O_VST2D ||
              op->opcode == O_VSTU2D || op->opcode == O_VSTL2D ||
              op->opcode == O_PFCHV)
            {
              print_ve_vopc_field(info, op->opcode, op->field.z,
                                      ins->gen.upper.w1.z, TRUE);
            }
          else if (ins->rv.x.bitx.cs2)
            {
              /* Cs2 is on */
              print_ve_vopc_field(info, op->opcode, op->field.z,
                                      ins->rv.y.y, TRUE);
            }
          else
            {
              print_ve_vopc_field(info, op->opcode, op->field.z,
                                      ins->gen.lower.w3.vz, FALSE);
            }
          comma = 1;
        }
      if (VE_OA_FMT(op->format) == FM_X_DYZ_WM)
        {
          (*info->fprintf_func)(info->stream, ")");
        }
      if (op->field.w)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          if (op->opcode == O_VFMAD || op->opcode == O_VFMSB ||
              op->opcode == O_VFNMAD || op->opcode == O_VFNMSB)
            {
              print_ve_vopc_field(info, op->opcode, op->field.w,
                                      ins->rv.vw, FALSE);
            }
          else
            {
              print_ve_vopc_field(info, op->opcode, op->field.w,
                                      ins->gen.upper.w1.y, TRUE);
            }
          comma = 1;
        }
      if (op->field.m)
        {
          if (comma && (ins->gen.upper.w1.x & 0x0f))
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          print_ve_vopc_field(info, op->opcode, op->field.m,
                                  ins->gen.upper.w1.x, FALSE);
        }
      break;
    case FM_XZYWM:
      /* format X,Z,Y,W,M */
      if (op->field.x)
        {
          print_ve_vopc_field(info, op->opcode, op->field.x,
                                  ins->gen.lower.w3.vx, FALSE);
          comma = 1;
        }
      if (op->field.z)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          print_ve_vopc_field(info, op->opcode, op->field.z,
                                  ins->gen.lower.w3.vz, FALSE);
          comma = 1;
        }
      if (op->field.y)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          print_ve_vopc_field(info, op->opcode, op->field.y,
                                  ins->gen.upper.w1.y, TRUE);
          comma = 1;
        }
      if (op->field.w)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          print_ve_vopc_field(info, op->opcode, op->field.w,
                                  ins->gen.upper.w1.z, TRUE);
          comma = 1;
        }
      if (op->field.m)
        {
          if (comma && (ins->gen.upper.w1.x & 0x0f))
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          print_ve_vopc_field(info, op->opcode, op->field.m,
                                  ins->gen.upper.w1.x, FALSE);
        }
      break;
    case FM_XWYZM:
      /* format X,W,Y,Z,M */
      if (op->field.x)
        {
          print_ve_vopc_field(info, op->opcode, op->field.x,
                                  ins->gen.lower.w3.vx, FALSE);
          comma = 1;
        }
      if (op->field.w)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
            if (ins->rvm.x.bitx.cs)
              {
                print_ve_vopc_field(info, op->opcode, op->field.w,
                                        ins->rvm.vw, FALSE);
              }
            else
              {
                print_ve_vopc_field(info, op->opcode, op->field.w,
                                        ins->rvm.vy, FALSE);
              }
            comma = 1;
        }
      if (op->field.y)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          print_ve_vopc_field(info, op->opcode, op->field.y,
                                  ins->rvm.y.y, TRUE);
          comma = 1;
        }
      if (op->field.z)
        {
          if (comma)
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          print_ve_vopc_field(info, op->opcode, op->field.z,
                                  ins->rvm.z.z, TRUE);
        }
      if (op->field.m)
        {
          if (comma && (ins->gen.upper.w1.x & 0x0f))
            {
              (*info->fprintf_func)(info->stream, ",");
            }
          print_ve_vopc_field(info, op->opcode, op->field.m,
                                  ins->gen.upper.w1.x, FALSE);
        }
      break;
    }
}

static void
print_operands(disassemble_info *info, ve_instr *ins, ve_opcode *op)
{
  if ((op->format & F_RV) || (op->format & F_RVM))
    {
      print_vector_operands(info, ins, op);
    }
  else
    {
      print_scalar_operands(info, ins, op);
    }
}

/* Print a VE instruction. */
int print_insn_ve (bfd_vma memaddr, disassemble_info *info)
{
  int len = -1;
  int status, iop;
  ve_instr inst;
  ve_opcode *op;

  /* We can expect at least 64 bit instruction code */
  status = (*info->read_memory_func)(memaddr, (bfd_byte *)&inst, 8, info);
  if (status)
    {
      (*info->memory_error_func)(status, memaddr, info);
      return -1;
    }
  len = 8;

  iop = ve_find_opc_index(&inst);
  if (iop < 0)
    {
      return len;
    }
  op = (ve_opcode *)&ve_opcodes[iop];

  /* print mnemonic */
  (*info->fprintf_func)(info->stream, "%s", op->name);

  (*info->fprintf_func)(info->stream, "\t");

  /* print operands */
  print_operands(info, &inst, op);

/*  (*info->fprintf_func)(info->stream, "\n"); */

  return len;
}

