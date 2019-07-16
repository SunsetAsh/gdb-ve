/* VE specific support for 64-bit ELF
   Copyright (C) 2014-2016 NEC Corporation.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "bfdlink.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "objalloc.h"
#include "hashtab.h"
#include "libiberty.h"
#include "elf-bfd.h"

#include "elf/ve.h"

#define TCB_OFFSET	0x30

/* A relocation fucntion which does not do anything. */
static bfd_reloc_status_type
elf64_ve_reloc_nil (bfd *abfd ATTRIBUTE_UNUSED, arelent *reloc,
                        asymbol *sym ATTRIBUTE_UNUSED,
                        void *data ATTRIBUTE_UNUSED, asection *sec,
                        bfd *output_bfd, char **error_message ATTRIBUTE_UNUSED)
{
  if (output_bfd)
    reloc->address += sec->output_offset;
  return bfd_reloc_ok;
}


/* This does not include any relocation information, but should be
   good enough for GDB or objdump to read the file.  */

static reloc_howto_type elf64_ve_howto_table[] = {
  /* reloc none */
  HOWTO (R_VE_NONE,		/* type */
	 0,			/* rightshift */
	 3,			/* size (0 = byte, 1 = short, 2 = long) */
	 0,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 elf64_ve_reloc_nil, /* special_function */
	 "R_VE_NONE",	/* name */
	 FALSE,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 32 bit reference to a symbol. */
  HOWTO (R_VE_REFLONG,	/* type */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 32,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special function */
	 "R_VE_REFLONG",	/* name */
	 FALSE,			/* partial_inplace */
	 0,			/* src_mask */
	 0xFFFFFFFF,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 64 bit reference to a symbol. */
  HOWTO (R_VE_REFQUAD,	/* type */
	 0,			/* rightshift */
	 4,			/* size (0 = byte, 1 = short, 2 = long) */
	 64,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special function */
	 "R_VE_REFQUAD",	/* name */
	 FALSE,			/* partial_inplace */
	 0,			/* src_mask */
	 0xFFFFFFFFFFFFFFFFLL,	/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 32 bit PC relative offset. */
  HOWTO (R_VE_SREL32,	/* type */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 32,			/* bitsize */
	 TRUE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_VE_SREL32",	/* name */
	 FALSE,			/* partial_inplace */
	 0,			/* src_mask */
	 0xFFFFFFFF,		/* dst_mask */
	 TRUE),			/* pcrel_offset */

  /* A 64 bit reference to the symbol virtual address.(bits 32-63)  */
  HOWTO (R_VE_HI32,         /* type */
         32,                    /* rightshift */
         2,                     /* size (0 = byte, 1 = short, 2 = long) */
         32,                    /* bitsize */
         FALSE,                 /* pc_relative */
         0,                     /* bitpos */
         complain_overflow_dont,        /* complain_on_overflow */
         bfd_elf_generic_reloc, /* special_function */
         "R_VE_HI32",       /* name */
         FALSE,                 /* partial_inplace */
         0,                     /* src_mask */
         0xFFFFFFFF,            /* dst_mask */
         FALSE),                /* pcrel_offset */

  /* A 64 bit reference to the symbol virtual address.(bits 0-31)  */
  HOWTO (R_VE_LO32,         /* type */
         0,                     /* rightshift */
         2,                     /* size (0 = byte, 1 = short, 2 = long) */
         32,                    /* bitsize */
         FALSE,                 /* pc_relative */
         0,                     /* bitpos */
         complain_overflow_dont,        /* complain_on_overflow */
         bfd_elf_generic_reloc, /* special_function */
         "R_VE_LO32",       /* name */
         FALSE,                 /* partial_inplace */
         0,                     /* src_mask */
         0xFFFFFFFF,            /* dst_mask */
         FALSE),                /* pcrel_offset */

  /* PC_HI32 */
  HOWTO (R_VE_PC_HI32,      /* type */
         32,                    /* rightshift */
         2,                     /* size (0 = byte, 1 = short, 2 = long) */
         32,                    /* bitsize */
         TRUE,                  /* pc_relative */
         0,                     /* bitpos */
         complain_overflow_dont,        /* complain_on_overflow */
         bfd_elf_generic_reloc, /* special_function */
         "R_VE_PC_HI32",    /* name */
         FALSE,                 /* partial_inplace */
         0,                     /* src_mask */
         0xFFFFFFFF,            /* dst_mask */
         TRUE),                 /* pcrel_offset */

  /* PC_LO32 */
  HOWTO (R_VE_PC_LO32,      /* type */
         0,                     /* rightshift */
         2,                     /* size (0 = byte, 1 = short, 2 = long) */
         32,                    /* bitsize */
         TRUE,                  /* pc_relative */
         0,                     /* bitpos */
         complain_overflow_dont,        /* complain_on_overflow */
         bfd_elf_generic_reloc, /* special_function */
         "R_VE_PC_LO32",    /* name */
         FALSE,                 /* partial_inplace */
         0,                     /* src_mask */
         0xFFFFFFFF,            /* dst_mask */
         TRUE),                 /* pcrel_offset */

  /* GOT32 */
  HOWTO (R_VE_GOT32,	/* type */
         0,			/* rightshift */
         4,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_signed, /* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special function */
         "R_VE_GOT32",	/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0xFFFFFFFF,		/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* GOT_HI32 */
  HOWTO (R_VE_GOT_HI32,     /* type */
         32,                    /* rightshift */
         2,                     /* size (0 = byte, 1 = short, 2 = long) */
         32,                    /* bitsize */
         FALSE,                 /* pc_relative */
         0,                     /* bitpos */
         complain_overflow_dont,        /* complain_on_overflow */
         bfd_elf_generic_reloc, /* special_function */
         "R_VE_GOT_HI32",   /* name */
         FALSE,                 /* partial_inplace */
         0,                     /* src_mask */
         0xFFFFFFFF,            /* dst_mask */
         FALSE),                /* pcrel_offset */

  /* GOT_LO32 */
  HOWTO (R_VE_GOT_LO32,     /* type */
         0,                     /* rightshift */
         2,                     /* size (0 = byte, 1 = short, 2 = long) */
         32,                    /* bitsize */
         FALSE,                 /* pc_relative */
         0,                     /* bitpos */
         complain_overflow_dont,        /* complain_on_overflow */
         bfd_elf_generic_reloc, /* special_function */
         "R_VE_GOT_LO32",   /* name */
         FALSE,                 /* partial_inplace */
         0,                     /* src_mask */
         0xFFFFFFFF,            /* dst_mask */
         FALSE),                /* pcrel_offset */

  /* GOTOFF32 */
  HOWTO (R_VE_GOTOFF32,	/* type */
         0,			/* rightshift */
         2,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_dont,	/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_VE_GOTOFF32",	/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0xFFFFFFFF,		/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* GOTOFF_HI32 */
  HOWTO (R_VE_GOTOFF_HI32,  /* type */
         32,                    /* rightshift */
         2,                     /* size (0 = byte, 1 = short, 2 = long) */
         32,                    /* bitsize */
         FALSE,                 /* pc_relative */
         0,                     /* bitpos */
         complain_overflow_dont,        /* complain_on_overflow */
         bfd_elf_generic_reloc, /* special_function */
         "R_VE_GOTOFF_HI32", /* name */
         FALSE,                 /* partial_inplace */
         0,                     /* src_mask */
         0xFFFFFFFF,            /* dst_mask */
         FALSE),                /* pcrel_offset */

  /* GOTOFF_LO32 */
  HOWTO (R_VE_GOTOFF_LO32,  /* type */
         0,                     /* rightshift */
         2,                     /* size (0 = byte, 1 = short, 2 = long) */
         32,                    /* bitsize */
         FALSE,                 /* pc_relative */
         0,                     /* bitpos */
         complain_overflow_dont,        /* complain_on_overflow */
         bfd_elf_generic_reloc, /* special_function */
         "R_VE_GOTOFF_LO32", /* name */
         FALSE,                 /* partial_inplace */
         0,                     /* src_mask */
         0xFFFFFFFF,            /* dst_mask */
         FALSE),                /* pcrel_offset */

  /* PLT32 */
  HOWTO (R_VE_PLT32,	/* type */
         0,			/* rightshift */
         2,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         TRUE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_dont,	/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special_function */
         "R_VE_PLT32",	/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0xFFFFFFFF,		/* dst_mask */
         TRUE),			/* pcrel_offset */

  /* PLT_HI32 */
  HOWTO (R_VE_PLT_HI32,     /* type */
         32,                    /* rightshift */
         2,                     /* size (0 = byte, 1 = short, 2 = long) */
         32,                    /* bitsize */
         TRUE,			/* pc_relative */
         0,                     /* bitpos */
         complain_overflow_dont,        /* complain_on_overflow */
         bfd_elf_generic_reloc, /* special_function */
         "R_VE_PLT_HI32",   /* name */
         FALSE,                 /* partial_inplace */
         0,                     /* src_mask */
         0xFFFFFFFF,            /* dst_mask */
         TRUE),			/* pcrel_offset */

  /* PLT_LO32 */
  HOWTO (R_VE_PLT_LO32,     /* type */
         0,                     /* rightshift */
         2,                     /* size (0 = byte, 1 = short, 2 = long) */
         32,                    /* bitsize */
         TRUE,			/* pc_relative */
         0,                     /* bitpos */
         complain_overflow_dont,        /* complain_on_overflow */
         bfd_elf_generic_reloc, /* special_function */
         "R_VE_PLT_LO32",   /* name */
         FALSE,                 /* partial_inplace */
         0,                     /* src_mask */
         0xFFFFFFFF,            /* dst_mask */
         TRUE),			/* pcrel_offset */

  /* RELATIVE */
  HOWTO (R_VE_RELATIVE,	/* type */
         0,			/* rightshift */
         4,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_dont, /* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special function */
         "R_VE_RELATIVE",	/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0xFFFFFFFF,		/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* GLOB_DAT */
  HOWTO (R_VE_GLOB_DAT,	/* type */
         0,			/* rightshift */
         4,			/* size (0 = byte, 1 = short, 2 = long) */
         64,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_dont, /* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special function */
         "R_VE_GLOB_DAT",	/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0xFFFFFFFFFFFFFFFFLL,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* JUMP_SLOT */
  HOWTO (R_VE_JUMP_SLOT,	/* type */
         0,			/* rightshift */
         4,			/* size (0 = byte, 1 = short, 2 = long) */
         64,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_dont, /* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special function */
         "R_VE_JUMP_SLOT",	/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0xFFFFFFFFFFFFFFFFLL,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* COPY */
  HOWTO (R_VE_COPY,		/* type */
         0,			/* rightshift */
         4,			/* size (0 = byte, 1 = short, 2 = long) */
         64,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_dont, /* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special function */
         "R_VE_COPY",	/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0xFFFFFFFFFFFFFFFFLL,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* IRELATIVE */
  HOWTO (R_VE_IRELATIVE,	/* type */
         0,			/* rightshift */
         4,			/* size (0 = byte, 1 = short, 2 = long) */
         64,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_bitfield, /* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special function */
         "R_VE_IRELATIVE",	/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0xFFFFFFFFFFFFFFFFLL,	/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* DTPMOD64 */
  HOWTO (R_VE_DTPMOD64,    /* type */
         0,                    /* rightshift */
         4,                    /* size (0 = byte, 1 = short, 2 = long) */
         64,                   /* bitsize */
         FALSE,                        /* pc_relative */
         0,                    /* bitpos */
         complain_overflow_dont,/* commplain_on_overflow */
         bfd_elf_generic_reloc, /* special function */
         "R_VE_DTPMOD64",  /* name */
         FALSE,                        /* partial_inplace */
         0,                    /* src_mask */
         0xFFFFFFFFFFFFFFFFLL, /* dst_mask */
         FALSE),               /* pcrel_offset */

  /* DTPOFF64 */
  HOWTO (R_VE_DTPOFF64,    /* type */
         0,                    /* rightshift */
         4,                    /* size (0 = byte, 1 = short, 2 = long) */
         64,                   /* bitsize */
         FALSE,                        /* pc_relative */
         0,                    /* bitpos */
         complain_overflow_dont,/* commplain_on_overflow */
         bfd_elf_generic_reloc, /* special function */
         "R_VE_DTPOFF64",  /* name */
         FALSE,                        /* partial_inplace */
         0,                    /* src_mask */
         0xFFFFFFFFFFFFFFFFLL, /* dst_mask */
         FALSE),               /* pcrel_offset */

  /* TPOFF64 */
  HOWTO (R_VE_TPOFF64,     /* type */
         0,                    /* rightshift */
         4,                    /* size (0 = byte, 1 = short, 2 = long) */
         64,                   /* bitsize */
         FALSE,                        /* pc_relative */
         0,                    /* bitpos */
         complain_overflow_dont,/* commplain_on_overflow */
         bfd_elf_generic_reloc, /* special function */
         "R_VE_TPOFF64",   /* name */
         FALSE,                        /* partial_inplace */
         0,                    /* src_mask */
         0xFFFFFFFFFFFFFFFFLL, /* dst_mask */
         FALSE),               /* pcrel_offset */

  /* TLS_GD_HI32 */
  HOWTO (R_VE_TLS_GD_HI32, /* type */
         32,                   /* rightshift */
         2,                    /* size (0 = byte, 1 = short, 2 = long) */
         32,                   /* bitsize */
         TRUE,                 /* pc_relative */
         0,                    /* bitpos */
         complain_overflow_dont,/* commplain_on_overflow */
         bfd_elf_generic_reloc, /* special function */
         "R_VE_TLS_GD_HI32",   /* name */
         FALSE,                /* partial_inplace */
         0,                    /* src_mask */
         0xFFFFFFFF,           /* dst_mask */
         TRUE),                /* pcrel_offset */

  /* TLS_GD_LO32 */
  HOWTO (R_VE_TLS_GD_LO32, /* type */
         0,                    /* rightshift */
         2,                    /* size (0 = byte, 1 = short, 2 = long) */
         32,                   /* bitsize */
         TRUE,                 /* pc_relative */
         0,                    /* bitpos */
         complain_overflow_dont,/* commplain_on_overflow */
         bfd_elf_generic_reloc,/* special function */
         "R_VE_TLS_GD_LO32",   /* name */
         FALSE,                /* partial_inplace */
         0,                    /* src_mask */
         0xFFFFFFFF,           /* dst_mask */
         TRUE),                /* pcrel_offset */

  /* TLS_LD_HI32 */
  HOWTO (R_VE_TLS_LD_HI32, /* type */
         32,                   /* rightshift */
         2,                    /* size (0 = byte, 1 = short, 2 = long) */
         32,                   /* bitsize */
         FALSE,                        /* pc_relative */
         0,                    /* bitpos */
         complain_overflow_dont,/* commplain_on_overflow */
         bfd_elf_generic_reloc, /* special function */
         "R_VE_TLS_LD_HI32",       /* name */
         FALSE,                        /* partial_inplace */
         0,                    /* src_mask */
         0xFFFFFFFF,           /* dst_mask */
         FALSE),               /* pcrel_offset */

  /* TLS_LD_LO32 */
  HOWTO (R_VE_TLS_LD_LO32, /* type */
         0,                    /* rightshift */
         2,                    /* size (0 = byte, 1 = short, 2 = long) */
         32,                   /* bitsize */
         FALSE,                        /* pc_relative */
         0,                    /* bitpos */
         complain_overflow_dont,/* commplain_on_overflow */
         bfd_elf_generic_reloc, /* special function */
         "R_VE_TLS_LD_LO32",       /* name */
         FALSE,                        /* partial_inplace */
         0,                    /* src_mask */
         0xFFFFFFFF,           /* dst_mask */
         FALSE),               /* pcrel_offset */

  /* DTPOFF32 */
  HOWTO (R_VE_DTPOFF32,    /* type */
         0,                    /* rightshift */
         2,                    /* size (0 = byte, 1 = short, 2 = long) */
         32,                   /* bitsize */
         FALSE,                        /* pc_relative */
         0,                    /* bitpos */
         complain_overflow_dont,/* commplain_on_overflow */
         bfd_elf_generic_reloc, /* special function */
         "R_VE_DTPOFF32",  /* name */
         FALSE,                        /* partial_inplace */
         0,                    /* src_mask */
         0xFFFFFFFF,           /* dst_mask */
         FALSE),               /* pcrel_offset */

  /* TLS_IE_HI32 */
  HOWTO (R_VE_TLS_IE_HI32,	/* type */
         32,			/* rightshift */
         2,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_dont,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special function */
         "R_VE_TLS_IE_HI32",/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0xFFFFFFFF,		/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* TLS_IE_LO32 */
  HOWTO (R_VE_TLS_IE_LO32,	/* type */
         0,			/* rightshift */
         2,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_dont,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special function */
         "R_VE_TLS_IE_HI32",/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0xFFFFFFFF,		/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* TPOFF_HI32 */
  HOWTO (R_VE_TPOFF_HI32,	/* type */
         32,			/* rightshift */
         2,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_dont,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special function */
         "R_VE_TPOFF_HI32",	/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0xFFFFFFFF,		/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* TPOFF_LO32 */
  HOWTO (R_VE_TPOFF_LO32,	/* type */
         0,			/* rightshift */
         2,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_dont,/* complain_on_overflow */
         bfd_elf_generic_reloc,	/* special function */
         "R_VE_TPOFF_LO32",	/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0xFFFFFFFF,		/* dst_mask */
         FALSE),		/* pcrel_offset */

  /* TPOFF32 */
  HOWTO (R_VE_TPOFF32,	/* type */
         0,			/* rightshift */
         2,			/* size (0 = byte, 1 = short, 2 = long) */
         32,			/* bitsize */
         FALSE,			/* pc_relative */
         0,			/* bitpos */
         complain_overflow_dont,/* complain_on_overflow */
         bfd_elf_generic_reloc, /* special function */
         "R_VE_TPOFF32",	/* name */
         FALSE,			/* partial_inplace */
         0,			/* src_mask */
         0xFFFFFFFF,		/* dst_mask */
         FALSE),		/* pcrel_offset */
};

#define IS_VE_PCREL_TYPE(TYPE) \
	(   ((TYPE) == R_VE_SREL32) \
         || ((TYPE) == R_VE_PC_HI32) \
         || ((TYPE) == R_VE_PC_LO32))

/* A mapping from BFD reloc types to VE ELF reloc types. */
struct elf_reloc_map
{
  bfd_reloc_code_real_type bfd_reloc_val;
  unsigned int elf_reloc_val;
};

static const struct elf_reloc_map elf64_ve_reloc_map[] =
{
  { BFD_RELOC_NONE,	R_VE_NONE },
  { BFD_RELOC_32,	R_VE_REFLONG },
  { BFD_RELOC_64,	R_VE_REFQUAD },
  { BFD_RELOC_32_PCREL, R_VE_SREL32 },
  { BFD_RELOC_VE_HI32,      R_VE_HI32 },
  { BFD_RELOC_VE_LO32,      R_VE_LO32 },
  { BFD_RELOC_VE_PC_HI32,   R_VE_PC_HI32 },
  { BFD_RELOC_VE_PC_LO32,   R_VE_PC_LO32 },
  { BFD_RELOC_VE_GOT32, R_VE_GOT32 },
  { BFD_RELOC_VE_GOT_HI32, R_VE_GOT_HI32 },
  { BFD_RELOC_VE_GOT_LO32, R_VE_GOT_LO32 },
  { BFD_RELOC_VE_GOTOFF32, R_VE_GOTOFF32 },
  { BFD_RELOC_VE_GOTOFF_HI32, R_VE_GOTOFF_HI32 },
  { BFD_RELOC_VE_GOTOFF_LO32, R_VE_GOTOFF_LO32 },
  { BFD_RELOC_VE_PLT32, R_VE_PLT32 },
  { BFD_RELOC_VE_PLT_HI32, R_VE_PLT_HI32 },
  { BFD_RELOC_VE_PLT_LO32, R_VE_PLT_LO32 },
  { BFD_RELOC_VE_RELATIVE, R_VE_RELATIVE },
  { BFD_RELOC_VE_GLOB_DAT, R_VE_GLOB_DAT },
  { BFD_RELOC_VE_JUMP_SLOT, R_VE_JUMP_SLOT },
  { BFD_RELOC_VE_COPY, R_VE_COPY },
  { BFD_RELOC_VE_IRELATIVE, R_VE_IRELATIVE },
  { BFD_RELOC_VE_DTPMOD64, R_VE_DTPMOD64 },
  { BFD_RELOC_VE_DTPOFF64, R_VE_DTPOFF64 },
  { BFD_RELOC_VE_TPOFF64, R_VE_TPOFF64 },
  { BFD_RELOC_VE_TLS_GD_HI32, R_VE_TLS_GD_HI32 },
  { BFD_RELOC_VE_TLS_GD_LO32, R_VE_TLS_GD_LO32 },
  { BFD_RELOC_VE_TLS_LD_HI32, R_VE_TLS_LD_HI32 },
  { BFD_RELOC_VE_TLS_LD_LO32, R_VE_TLS_LD_LO32 },
  { BFD_RELOC_VE_DTPOFF32, R_VE_DTPOFF32 },
  { BFD_RELOC_VE_TLS_IE_HI32, R_VE_TLS_IE_HI32 },
  { BFD_RELOC_VE_TLS_IE_LO32, R_VE_TLS_IE_LO32 },
  { BFD_RELOC_VE_TPOFF_HI32, R_VE_TPOFF_HI32 },
  { BFD_RELOC_VE_TPOFF_LO32, R_VE_TPOFF_LO32 },
  { BFD_RELOC_VE_TPOFF32, R_VE_TPOFF32 },
};

static reloc_howto_type *
elf_ve_rtype_to_howto(bfd *abfd, unsigned int r_type)
{
  if (r_type >= R_VE_max)
    {
      (*_bfd_error_handler)(_("%B: invalid relocation type %d"),
                            abfd, (int)r_type);
      r_type = R_VE_NONE;
    }
  BFD_ASSERT(elf64_ve_howto_table[r_type].type == r_type);
  return &elf64_ve_howto_table[r_type];
}

/* Given a BFD reloc type, return a HOWTO structure. */
static reloc_howto_type *
elf_ve_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                                    bfd_reloc_code_real_type code)
{
  const struct elf_reloc_map *i, *e;

  i = e = elf64_ve_reloc_map;
  e += sizeof (elf64_ve_reloc_map) / sizeof (struct elf_reloc_map);
  for (; i != e; i++)
    {
      if (i->bfd_reloc_val == code)
        return &elf64_ve_howto_table[i->elf_reloc_val];
    }
  return 0;
}

static reloc_howto_type *
elf_ve_reloc_name_lookup(bfd *abfd ATTRIBUTE_UNUSED,
                                 const char *r_name)
{
  unsigned int i;

  for (i = 0;
       i < (sizeof (elf64_ve_howto_table)
            / sizeof (elf64_ve_howto_table[0]));
       i++)
    {
      if (elf64_ve_howto_table[i].name != NULL &&
          strcasecmp (elf64_ve_howto_table[i].name, r_name) == 0)
        return &elf64_ve_howto_table[i];
    }

  return NULL;
}

static void
elf_ve_info_to_howto(bfd *abfd ATTRIBUTE_UNUSED,
                         arelent *cache_ptr, Elf_Internal_Rela *dst)
{
  unsigned r_type = ELF64_R_TYPE(dst->r_info);
  BFD_ASSERT (r_type < (unsigned int ) R_VE_max);
  cache_ptr->howto = &elf64_ve_howto_table[r_type];
}

/* Support for core dump NOTE sections.  */
static bfd_boolean
elf_ve_grok_prstatus (bfd *abfd, Elf_Internal_Note *note)
{
  int offset;
  size_t size;

  switch (note->descsz)
    {
    default:
      return FALSE;

    case 6264:	/* sizeof(struct elf_prstatus) on Linux/ve */
      /* pr_cursig */
      elf_tdata (abfd)->core->signal = bfd_get_16 (abfd, note->descdata + 12);

      /* pr_pid */
      elf_tdata (abfd)->core->lwpid = bfd_get_32 (abfd, note->descdata + 32);

      /* pr_reg */
      offset = 112;
      size = 6144;

      break;
    }

  /* Make a ".reg/999" section.  */
  return _bfd_elfcore_make_pseudosection (abfd, ".reg",
					  size, note->descpos + offset);
}

static bfd_boolean
elf_ve_grok_psinfo (bfd *abfd, Elf_Internal_Note *note)
{
  switch (note->descsz)
    {
    default:
      return FALSE;

    case 136:		/* sizeof(struct elf_prpsinfo) on Linux/ve */
      elf_tdata (abfd)->core->pid = bfd_get_32 (abfd, note->descdata + 24);
      elf_tdata (abfd)->core->program
        = _bfd_elfcore_strndup (abfd, note->descdata + 40, 16);
      elf_tdata (abfd)->core->command
        = _bfd_elfcore_strndup (abfd, note->descdata + 56, 80);
    }

  /* Note that for some reason, a spurious space is tacked
     onto the end of the args in some (at least one anyway)
     implementations, so strip it off if it exists.  */

  {
    char *command = elf_tdata (abfd)->core->command;
    int n = strlen (command);

    if (0 < n && command[n - 1] == ' ')
      command[n - 1] = '\0';
  }

  return TRUE;
}

/* The name of the dynamic interpreter. This is put in the .interp
   section. */
#define ELF_DYNAMIC_INTERPRETER		"/opt/nec/ve/lib/ld.so.1"

/* If ELIMINATE_COPY_RELOCS is non-zero, the linker will try to avoid
   copying dynamic variables from a shared lib into an app's dynbss
   section, and instead use a dynamic relocation to point into the
   shared lib. */
#define ELIMINATE_COPY_RELOCS		1

/* The size in bytes of an entry in the global offset table. */
#define GOT_ENTRY_SIZE			8

/* The size in bytes of an entry in the procedure linkage table. */
#define PLT_ENTRY_SIZE			8*8

static const unsigned long elf_ve_plt0_entry[PLT_ENTRY_SIZE / 8] =
{
  0x060f000000000000,	/* lea %got,_GLOBAL_OFFSET_TABLE_@LO */
  0x440f8f6000000000,	/* and %got,%got,(32)0 */
  0x068f008f00000000,	/* lea.sl %got,_GLOBAL_OFFSET_TABLE_@HI(,%got) */
  0x013f008f00000008,	/* ld %s63,0x8(0,%got) */
  0x193f00bf00000000,	/* b.l.t 0x0(,%s63) */
  0x7900000000000000,	/* nop */
  0x7900000000000000,	/* nop */
  0x7900000000000000 	/* nop */
};

static const unsigned long elf_ve_plt0_entry_pic[PLT_ENTRY_SIZE / 8] =
{
  0x013f008f00000008,  /* ld %s63,0x8(0,%got) */
  0x193f00bf00000000,  /* b.l.t 0x0(,%s63) */
  0x7900000000000000,  /* nop */
  0x7900000000000000,  /* nop */
  0x7900000000000000,  /* nop */
  0x7900000000000000,  /* nop */
  0x7900000000000000,  /* nop */
  0x7900000000000000   /* nop */
};

static const unsigned long elf_ve_plt_entry[PLT_ENTRY_SIZE / 8] =
{
  0x060d000000000000,	/* lea %s13,funcN@GOT_LO or LO */
  0x440d8d6000000000,	/* and %s13,%s13,(32)0 */
  0x068d8f8d00000000,	/* lea.sl %s13,funcN@GOT_HI(%s13,%got) or HI(,%s13) */
  0x010d008d00000000,	/* ld  %s13,(,%s13) */
  0x193f008d00000000,	/* b.l.t (,%s13) */
  0x060d000000000000,	/* lea %s13, N */
#if 1
  0x183f000000000000,	/* br.l.t _PROCEDURE_LINKAGE_TABLE_ */
#else
  0x193f009000000000,	/* b.l.t (,%s16) */
#endif
  0x7900000000000000 	/* nop */
};

/* The name of the dynamic relocation section. */
#define VE_ELF_REL_DYN_NAME		".rela.dyn"

/* The default alignment for sections, as a power of two. */
#define VE_ELF_LOG_FILE_ALIGN(abfd) \
  (get_elf_backend_data(abfd)->s->log_file_align)

/* Return size of a relocation entry. */
#define RELOC_SIZE(HTAB)        (sizeof(Elf64_External_Rela))

/* Get the VE ELF linker hash table from a link_info structure. */
#define elf_ve_hash_table(p) \
  ((struct elf_ve_link_hash_table *)((p)->hash))

/* VE ELF linker hash entry. */
struct elf_ve_link_hash_entry
{
  struct elf_link_hash_entry root;

  /* Track dynamic relocs copied for this symbol. */
  struct elf_dyn_relocs *dyn_relocs;

#define GOT_UNKNOWN	0
#define GOT_NORMAL	1
#define GOT_TLS_GD	2
#define GOT_TLS_IE	3
#define GOT_TLS_LE	4
  unsigned char got_type;

  /* Offset of the GOTPLT entry reserved for the TLS descriptor,
     starting at the end of the jump table. */
  bfd_vma tlsdesc_got;

  /* TODO */
};

#define elf_ve_hash_entry(ent) \
	((struct elf_ve_link_hash_entry *)(ent))

struct elf_ve_obj_tdata
{
  struct elf_obj_tdata root;

  /* tls_type for each local got entry. */
  char *local_got_tls_type;

  /* GOTPLT entries for TLS descriptors. */
  bfd_vma *local_tlsdesc_gotent;

  /* TODO */
};

#define elf_ve_tdata(abfd) \
	((struct elf_ve_obj_tdata *)(abfd)->tdata.any)

#define elf_ve_local_got_tls_type(abfd) \
	(elf_ve_tdata(abfd)->local_got_tls_type)

#define elf_ve_local_tlsdesc_gotent(abfd) \
	(elf_ve_tdata(abfd)->local_tlsdesc_gotent)

static bfd_boolean
elf_ve_mkobject(bfd *abfd)
{
  return bfd_elf_allocate_object(abfd, sizeof(struct elf_ve_obj_tdata),
                                 VE_ELF_DATA);
}

/* VE ELF linker hash table. */
struct elf_ve_link_hash_table
{
  struct elf_link_hash_table root;

  /* The number of bytes in the initial entry in the PLT. */
  bfd_size_type plt_header_size;

  /* The number of bytes in the subsequent PLT entries. */
  bfd_size_type plt_entry_size;

  /* Shortcuts to some dynamic sections, or NULL if they are not. */
  asection *sdynbss;
  asection *srelbss;
  asection *plt_eh_frame;

  union
  {
    bfd_signed_vma refcount;
    bfd_vma offset;
  } tls_ld_got;

  /* Small local sym cache. */
  struct sym_cache sym_cache;

  /* Used by local STT_GNU_IFUNC symbols. */
  htab_t loc_hash_table;
  void *loc_hash_memory;

  /* The amount of space used by the jump slots in the GOT. */
  bfd_vma sgotplt_jump_table_size;

  /* The index of the next R_VE_JUMP_SLOT entry in .rela.plt. */
  bfd_vma next_jump_slot_index;
  /* The index of hte next R_VE_IRELATIVE entry in .rela.plt. */
  bfd_vma next_irelative_index;

  /* Offset into plt entry where the initial value of the GOT entry points. */
  bfd_vma plt_lazy_offset;

  /* Offset into plt_entry that are to be replaced with 
     offset to start of .plt */
  bfd_vma plt_plt_offset;

  /* address of this symbol in .got */
  bfd_vma plt_got_offset;
};

/* Create an entry in an VE ELF linker hash table. */
static struct bfd_hash_entry *
elf_ve_link_hash_newfunc(struct bfd_hash_entry *entry,
                             struct bfd_hash_table *table,
                             const char *string)
{
  struct elf_ve_link_hash_entry *ret =
    (struct elf_ve_link_hash_entry *)entry;

  if (ret == (struct elf_ve_link_hash_entry *)NULL)
    ret = (struct elf_ve_link_hash_entry *)
            bfd_hash_allocate(table, sizeof(struct elf_ve_link_hash_entry));
  if (ret == (struct elf_ve_link_hash_entry *)NULL)
    return (struct bfd_hash_entry *)ret;

  ret = (struct elf_ve_link_hash_entry *)
          _bfd_elf_link_hash_newfunc((struct bfd_hash_entry *)ret,
                                     table, string);

  if (ret != NULL)
    {
      ret->dyn_relocs = NULL;
      ret->got_type = GOT_UNKNOWN;
    }
  /* TODO */

  return (struct bfd_hash_entry *)ret;
}

/* Compute a hash of a local hash entry. */
static hashval_t
elf_ve_local_htab_hash(const void *ptr)
{
  struct elf_link_hash_entry *h = (struct elf_link_hash_entry *)ptr;
  return ELF_LOCAL_SYMBOL_HASH(h->indx, h->dynstr_index);
}

static int
elf_ve_local_htab_eq(const void *ptr1, const void *ptr2)
{
  struct elf_link_hash_entry *h1 = (struct elf_link_hash_entry *)ptr1;
  struct elf_link_hash_entry *h2 = (struct elf_link_hash_entry *)ptr2;

  return h1->indx == h2->indx && h1->dynstr_index == h2->dynstr_index;
}

static struct elf_link_hash_entry *
elf_ve_get_local_sym_hash(struct elf_ve_link_hash_table *htab,
                              bfd *abfd, const Elf_Internal_Rela *rel,
                              bfd_boolean create)
{
  struct elf_ve_link_hash_entry e, *ret;
  asection *sec = abfd->sections;
  hashval_t h = ELF_LOCAL_SYMBOL_HASH(sec->id, ELF64_R_SYM(rel->r_info));
  void **slot;

  e.root.indx = sec->id;
  e.root.dynstr_index = ELF64_R_SYM(rel->r_info);
  slot = htab_find_slot_with_hash(htab->loc_hash_table, &e, h,
                                  create ? INSERT : NO_INSERT);

  if (!slot)
    return NULL;

  if (*slot)
    {
      ret = (struct elf_ve_link_hash_entry *)*slot;
      return &ret->root;
    }

  ret = (struct elf_ve_link_hash_entry *)
        objalloc_alloc((struct objalloc *)htab->loc_hash_memory,
                       sizeof(struct elf_ve_link_hash_entry));
  if (ret)
    {
      memset(ret, 0, sizeof(*ret));
      ret->root.indx = sec->id;
      ret->root.dynstr_index = ELF64_R_SYM(rel->r_info);
      ret->root.dynindx = -1;
      *slot = ret;
    }
  return &ret->root;
}

/* Destroy an VE ELF linker hash table. */
static void
elf_ve_link_hash_table_free(bfd *obfd)
{
  struct elf_ve_link_hash_table *htab
    = (struct elf_ve_link_hash_table *)obfd->link.hash;

  if (htab->loc_hash_table)
    htab_delete(htab->loc_hash_table);
  if (htab->loc_hash_memory)
    objalloc_free((struct objalloc *)htab->loc_hash_memory);
  _bfd_elf_link_hash_table_free(obfd);
}

/* Create an VE ELF linker hash table. */
static struct bfd_link_hash_table *
elf_ve_link_hash_table_create(bfd *abfd)
{
  struct elf_ve_link_hash_table *ret;
  bfd_size_type amt = sizeof(struct elf_ve_link_hash_table);

  ret = bfd_zmalloc(amt);
  if (ret == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init(&ret->root, abfd,
                                     elf_ve_link_hash_newfunc,
                                     sizeof(struct elf_ve_link_hash_entry),
                                     VE_ELF_DATA))
    {
      free(ret);
      return NULL;
    }

  ret->plt_header_size = PLT_ENTRY_SIZE;
  ret->plt_entry_size = PLT_ENTRY_SIZE;

  ret->loc_hash_table = htab_try_create(1024,
                                        elf_ve_local_htab_hash,
                                        elf_ve_local_htab_eq,
                                        NULL);
  ret->loc_hash_memory = objalloc_create();
  if (!ret->loc_hash_table || !ret->loc_hash_memory)
    {
      elf_ve_link_hash_table_free(abfd);
      return NULL;
    }
  ret->root.root.hash_table_free = elf_ve_link_hash_table_free;

  ret->plt_lazy_offset = 40;
  ret->plt_plt_offset = 48;
  ret->plt_got_offset = 16;

  return &ret->root.root;
}

static bfd_boolean
elf_ve_close_and_cleanup(bfd *abfd)
{
#if 0
  if (abfd->sections)
    bfd_map_over_sections(abfd, unrecord_section_via_map_over_sections, NULL);
#endif

  return _bfd_elf_close_and_cleanup(abfd);
}

static bfd_boolean
elf_ve_free_cached_info(bfd *abfd)
{
#if 0
  if (abfd->sections)
    bfd_map_over_sections(abfd, unrecord_section_via_map_over_sections, NULL);
#endif

  return _bfd_free_cached_info(abfd);
}

static bfd_reloc_code_real_type
elf_ve_bfd_reloc_from_type(unsigned int r_type)
{
  unsigned int i;
  const struct elf_reloc_map *rel = elf64_ve_reloc_map;

  for (i = 0; i < ARRAY_SIZE(elf64_ve_reloc_map); i++)
    {
      if ((unsigned int)(rel[i].elf_reloc_val) == r_type)
        return elf64_ve_reloc_map[i].bfd_reloc_val;
    }

  return 0;
}

static reloc_howto_type *
elf_ve_howto_from_type(unsigned int r_type)
{
  bfd_reloc_code_real_type val;
  reloc_howto_type *howto;

  val = elf_ve_bfd_reloc_from_type(r_type);
  howto = elf_ve_reloc_type_lookup(NULL, val);

  if (howto != NULL)
    return howto;

  bfd_set_error(bfd_error_bad_value);
  return NULL;
}

/* Copy backend specific data from one object module to another. */
static bfd_boolean
elf_ve_copy_private_bfd_data(bfd *ibfd, bfd *obfd)
{
  flagword in_flags;

  in_flags = elf_elfheader(ibfd)->e_flags;

  elf_elfheader(obfd)->e_flags = in_flags;
  elf_flags_init(obfd) = TRUE;

  /* Also copy the EI_OSABI field. */
  elf_elfheader(obfd)->e_ident[EI_OSABI]
    = elf_elfheader(ibfd)->e_ident[EI_OSABI];

  /* Copy object attributes. */
  _bfd_elf_copy_obj_attributes(ibfd, obfd);

  return TRUE;
}

/* Merge backend specific data from an object file to the output object
   file when linking. */
static bfd_boolean
elf_ve_merge_private_bfd_data(bfd *ibfd, bfd *obfd)
{
  flagword in_flags, out_flags;
  asection *sec;

  /* Check if the same endianess. */
  if (!_bfd_generic_verify_endian_match(ibfd, obfd))
    return FALSE;

  in_flags = elf_elfheader(ibfd)->e_flags;
  out_flags = elf_elfheader(ibfd)->e_flags;

  if (!elf_flags_init(obfd))
    {
      elf_flags_init(obfd) = TRUE;
      elf_elfheader(obfd)->e_flags = in_flags;

      return TRUE;
    }

  if (in_flags == out_flags)
    return TRUE;

  if (!(ibfd->flags & DYNAMIC))
    {
      bfd_boolean null_input_bfd = TRUE;
      bfd_boolean only_data_sections = TRUE;

      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
        {
          if ((bfd_get_section_flags(ibfd, sec)
               & (SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS))
              == (SEC_LOAD | SEC_CODE | SEC_HAS_CONTENTS))
            only_data_sections = FALSE;

          null_input_bfd = FALSE;
          break;
        }

      if (null_input_bfd || only_data_sections)
        return TRUE;
    }

  return TRUE;
}

/* Display the flags field. */
static bfd_boolean
elf_ve_print_private_bfd_data(bfd *abfd, void *ptr)
{
#if 0 /* TODO */
  FILE *file = (FILE *)ptr;
  unsigned long flags;
#endif /* TODO */

  /* Print normal ELF private data. */
  _bfd_elf_print_private_bfd_data(abfd, ptr);

#if 0 /* TODO */
  flags = elf_elfheader(abfd)->e_flags;

  fprintf(file, _("private flags = %lx:"), elf_elfheader(abfd)->e_flags);

  if (flags)
    fprintf(file, _("<Unrecognised flag bits set>"));

  fputc('\n', file);
#endif /* TODO */

  return TRUE;
}

/* Create .plt, .rela.plt, .got, .got.plt, .rela.got, .dynbss, and
   .rela.bss sections in DYNOBJ, and set up shortcuts to them in our
   hash table. */
static bfd_boolean
elf_ve_create_dynamic_sections(bfd *dynobj, struct bfd_link_info *info)
{
  struct elf_ve_link_hash_table *htab;

  if (!_bfd_elf_create_dynamic_sections(dynobj, info))
    return FALSE;

  htab = elf_ve_hash_table(info);
  if (htab == NULL)
    return FALSE;

  htab->sdynbss = bfd_get_linker_section(dynobj, ".dynbss");
  if (!bfd_link_pic(info))
    htab->srelbss = bfd_get_linker_section(dynobj, ".rela.bss");

  if (!htab->sdynbss || (!bfd_link_pic(info) && !htab->srelbss))
    abort();

  if (bfd_link_executable(info))
    {
      /* Always allow copy relocs for building executables.  */
      asection *s = bfd_get_linker_section (dynobj, ".rela.bss");
      if (s == NULL)
        {
          const struct elf_backend_data *bed = get_elf_backend_data (dynobj);
          s = bfd_make_section_anyway_with_flags(dynobj,
                                                 ".rela.bss",
                                                 (bed->dynamic_sec_flags
                                                  | SEC_READONLY));
          if (s == NULL
              || ! bfd_set_section_alignment(dynobj, s,
                                             bed->s->log_file_align))
            return FALSE;
        }
      htab->srelbss = s;
    }

  if (!info->no_ld_generated_unwind_info
      && htab->plt_eh_frame == NULL
      && htab->root.splt != NULL)
    {
      flagword flags = (SEC_ALLOC | SEC_LOAD | SEC_READONLY
                        | SEC_HAS_CONTENTS | SEC_IN_MEMORY
                        | SEC_LINKER_CREATED);
      htab->plt_eh_frame
        = bfd_make_section_anyway_with_flags(dynobj, ".eh_frame", flags);
      if (htab->plt_eh_frame == NULL
          || !bfd_set_section_alignment(dynobj, htab->plt_eh_frame, 3))
        return FALSE;
    }

  return TRUE;
}

static void
elf_ve_copy_indirect_symbol(struct bfd_link_info *info,
                                struct elf_link_hash_entry *dir,
                                struct elf_link_hash_entry *ind)
{
  struct elf_ve_link_hash_entry *edir, *eind;

  edir = (struct elf_ve_link_hash_entry *)dir;
  eind = (struct elf_ve_link_hash_entry *)ind;

  if (eind->dyn_relocs != NULL)
    {
      if (edir->dyn_relocs != NULL)
        {
          struct elf_dyn_relocs **pp;
          struct elf_dyn_relocs *p;

          for (pp = &eind->dyn_relocs; (p = *pp) != NULL;)
            {
              struct elf_dyn_relocs *q;

              for (q = edir->dyn_relocs; q != NULL; q = q->next)
                if (q->sec == p->sec)
                  {
                    q->pc_count += p->pc_count;
                    q->count += p->count;
                    *pp = p->next;
                    break;
                  }
              if (q == NULL)
                pp = &p->next;
            }
          *pp = edir->dyn_relocs;
        }

      edir->dyn_relocs = eind->dyn_relocs;
      eind->dyn_relocs = NULL;
    }

  if (ind->root.type == bfd_link_hash_indirect && dir->got.refcount <= 0)
    {
      edir->got_type = eind->got_type;
      eind->got_type = GOT_UNKNOWN;
    }

  if (ELIMINATE_COPY_RELOCS
      && ind->root.type != bfd_link_hash_indirect && dir->dynamic_adjusted)
    {
      dir->ref_dynamic |= ind->ref_dynamic;
      dir->ref_regular |= ind->ref_regular;
      dir->ref_regular_nonweak |= ind->ref_regular_nonweak;
      dir->needs_plt |= ind->needs_plt;
      dir->pointer_equality_needed |= ind->pointer_equality_needed;
    }
  else
    _bfd_elf_link_hash_copy_indirect(info, dir, ind);
}

static bfd_boolean
elf_ve_elf_object_p(bfd *abfd ATTRIBUTE_UNUSED)
{
  /* TODO */
  return TRUE;
}

/* Return TRUE if the TLS access code sequence support transition from
   R_TYPE. */
static bfd_boolean
elf_ve_check_tls_transition(bfd *abfd,
                                struct bfd_link_info *info ATTRIBUTE_UNUSED,
                                asection *sec,
                                bfd_byte *contents,
                                Elf_Internal_Shdr *symtab_hdr ATTRIBUTE_UNUSED,
                                struct elf_link_hash_entry **sym_hashes ATTRIBUTE_UNUSED,
                                unsigned int r_type,
                                const Elf_Internal_Rela *rel,
                                const Elf_Internal_Rela *relend)
{
  bfd_vma offset;

  /* Get the section contents. */
  if (contents == NULL)
    {
      if (elf_section_data(sec)->this_hdr.contents != NULL)
        contents = elf_section_data(sec)->this_hdr.contents;
      else
        {
          if (!bfd_malloc_and_get_section(abfd, sec, &contents))
            return FALSE;

          elf_section_data(sec)->this_hdr.contents = contents;
        }
    }

  offset = rel->r_offset;
  switch (r_type)
    {
    case R_VE_TLS_GD_HI32:
      if ((rel + 2) >= relend)
        return FALSE;

      if ((offset + 40) > sec->size)
          return FALSE;

      return TRUE;

    case R_VE_TLS_GD_LO32:
      if ((rel + 3) >= relend)
        return FALSE;

      if ((offset + 64) > sec->size)
        return FALSE;

      return TRUE;

    case R_VE_TLS_IE_HI32:
      if ((rel + 2) >= relend)
        return FALSE;

      return TRUE;

    case R_VE_TLS_IE_LO32:
      if ((rel + 1) >= relend)
        return FALSE;

      return TRUE;
    }

  return FALSE;
}

/* Return TRUE if the TLS access transition is OK or no transition
   will be performed. */
static bfd_boolean
elf_ve_tls_transition(struct bfd_link_info *info,
                          bfd *abfd,
                          asection *sec,
                          bfd_byte *contents,
                          Elf_Internal_Shdr *symtab_hdr,
                          struct elf_link_hash_entry **sym_hashes,
                          unsigned int *r_type,
                          int got_type,
                          const Elf_Internal_Rela *rel,
                          const Elf_Internal_Rela *relend,
                          struct elf_link_hash_entry *h,
                          unsigned long r_symndx)
{
  unsigned int from_type = *r_type;
  unsigned int to_type = from_type;
  bfd_boolean check = TRUE;

  /* Skip TLS transition for functins. */
  if (h != NULL
      && (h->type == STT_FUNC || h->type == STT_GNU_IFUNC))
    return TRUE;

  switch (from_type)
    {
    case R_VE_TLS_GD_HI32:
    case R_VE_TLS_GD_LO32:
      if (bfd_link_executable(info))
        {
          if (h == NULL ||
              (h->def_regular && h->ref_regular))
            to_type = (from_type == R_VE_TLS_GD_HI32) ?
                          R_VE_TPOFF_HI32 : R_VE_TPOFF_LO32;
          else
            to_type = from_type;
        }

      if (contents != NULL)
        {
          unsigned int new_to_type = to_type;

          if (bfd_link_executable (info)
              && h != NULL
              && h->dynindx == -1
              && got_type == GOT_TLS_IE)
            {
              new_to_type = (from_type == R_VE_TLS_GD_HI32) ?
                                R_VE_TPOFF_HI32 : R_VE_TPOFF_LO32;
            }
          check = new_to_type != to_type && from_type == to_type;
          to_type = new_to_type;
        }
      break;
    default:
      return TRUE;
    }

  /* Return TRUE if there is no transition. */
  if (from_type == to_type)
    return TRUE;

  /* Check if the transition can be performed. */
  if (check
      && !elf_ve_check_tls_transition(abfd, info, sec, contents,
                                          symtab_hdr, sym_hashes,
                                          from_type, rel, relend))
    {
      reloc_howto_type *from, *to;
      const char *name;

      from = elf_ve_rtype_to_howto(abfd, from_type);
      to = elf_ve_rtype_to_howto(abfd, to_type);

      if (h)
        name = h->root.root.string;
      else
        {
          struct elf_ve_link_hash_table *htab;

          htab = elf_ve_hash_table(info);
          if (htab == NULL)
            name = "*unknown*";
          else
            {
              Elf_Internal_Sym *isym;

              isym = bfd_sym_from_r_symndx(&htab->sym_cache, abfd, r_symndx);
              name = bfd_elf_sym_name(abfd, symtab_hdr, isym, NULL);
            }
        }

      (*_bfd_error_handler)
        (_("%B: TLS transition from %s to %s against `%s' at 0x%lx "
           "in section `%A' failed"),
         abfd, sec, from->name, to->name, name, (unsigned long)rel->r_offset);
      bfd_set_error(bfd_error_bad_value);
      return FALSE;
    }

  *r_type = to_type;
  return TRUE;
}

/* Look through the relocs for a section during the first phase, and
   calculate needed space in the global offset table, proceduer linkage
   table, and dynamic reloc sections. */
static bfd_boolean
elf_ve_check_relocs(bfd *abfd, struct bfd_link_info *info,
                        asection *sec, const Elf_Internal_Rela *relocs)
{
  struct elf_ve_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  const Elf_Internal_Rela *rel;
  const Elf_Internal_Rela *rel_end;
  asection *sreloc;

  if (bfd_link_relocatable(info))
    return TRUE;

  htab = elf_ve_hash_table(info);
  if (htab == NULL)
    return FALSE;

  symtab_hdr = &elf_symtab_hdr(abfd);
  sym_hashes = elf_sym_hashes(abfd);
  sreloc = NULL;

  rel_end = relocs + sec->reloc_count;
  for (rel = relocs; rel < rel_end; rel++)
    {
      unsigned int r_type;
      unsigned long r_symndx;
      struct elf_link_hash_entry *h;
      Elf_Internal_Sym *isym;
      const char *name;
      bfd_boolean size_reloc;

      r_symndx = ELF64_R_SYM(rel->r_info);
      r_type = ELF64_R_TYPE(rel->r_info);

      if (r_symndx >= NUM_SHDR_ENTRIES(symtab_hdr))
        {
          (*_bfd_error_handler)(_("%B: bad symbol index: %d"), abfd, r_symndx);
          return FALSE;
        }

      if (r_symndx < symtab_hdr->sh_info)
        {
          /* A local symbol. */
          isym = bfd_sym_from_r_symndx(&htab->sym_cache, abfd, r_symndx);
          if (isym == NULL)
            return FALSE;

          /* Check relocation against local STT_GNU_IFUNC symbol. */
          if (ELF_ST_TYPE(isym->st_info) == STT_GNU_IFUNC)
            {
              h = elf_ve_get_local_sym_hash(htab, abfd, rel, TRUE);
              if (h == NULL)
                return FALSE;

              /* Fake a STT_GNU_IFUNC symbol. */
              h->type = STT_GNU_IFUNC;
              h->def_regular = 1;
              h->ref_regular = 1;
              h->forced_local = 1;
              h->root.type = bfd_link_hash_defined;
            }
          else
            h = NULL;
        }
      else
        {
          isym = NULL;
          h = sym_hashes[r_symndx - symtab_hdr->sh_info];
          while (h->root.type == bfd_link_hash_indirect
                 || h->root.type == bfd_link_hash_warning)
            h = (struct elf_link_hash_entry *)h->root.u.i.link;
        }

      if (h != NULL)
        {
          switch (r_type)
            {
            default:
              break;

            case R_VE_REFQUAD:
            case R_VE_REFLONG:
            case R_VE_SREL32:
            case R_VE_PC_HI32:
            case R_VE_PC_LO32:
            case R_VE_PLT32:
            case R_VE_PLT_HI32:
            case R_VE_PLT_LO32:
              if (htab->root.dynobj == NULL)
                htab->root.dynobj = abfd;
              if (!_bfd_elf_create_ifunc_sections(htab->root.dynobj, info))
                return FALSE;
              break;
            }

          /* It is referenced by a non-shared object. */
          h->ref_regular = 1;
          h->root.non_ir_ref = 1;
        }

      if (!elf_ve_tls_transition(info, abfd, sec, NULL, symtab_hdr,
                                     sym_hashes, &r_type, GOT_UNKNOWN,
                                     rel, rel_end, h, r_symndx))
        return FALSE;

      switch (r_type)
        {
        case R_VE_TLS_LD_HI32:
        case R_VE_TLS_LD_LO32:
          htab->tls_ld_got.refcount += 1;
          goto create_got;

        case R_VE_TPOFF64:
          if (!bfd_link_executable(info))
            {
              if (h)
                name = h->root.root.string;
              else
                name = bfd_elf_sym_name(abfd,symtab_hdr,isym,NULL);
              (*_bfd_error_handler)
                (_("%B: relocation %s against `%s' can not be used when making a shared object; recompile with -fPIC"), 
                abfd,
                elf64_ve_howto_table[r_type].name, name);
              bfd_set_error(bfd_error_bad_value);
              return FALSE;
            }
          break;

        case R_VE_TLS_IE_HI32:
        case R_VE_TLS_IE_LO32:
          if (bfd_link_pic(info))
            info->flags |= DF_STATIC_TLS;
          /* Fall through */

        case R_VE_GOT32:
        case R_VE_GOT_HI32:
        case R_VE_GOT_LO32:
        case R_VE_TLS_GD_HI32:
        case R_VE_TLS_GD_LO32:
          /* This symbol requires a global offset table entry. */
          {
            int got_type, old_got_type;

            switch (r_type)
              {
              default:
                got_type = GOT_NORMAL;
                break;
              case R_VE_TLS_GD_HI32:
              case R_VE_TLS_GD_LO32:
                got_type = GOT_TLS_GD;
                break;
              case R_VE_TLS_IE_HI32:
              case R_VE_TLS_IE_LO32:
                got_type = GOT_TLS_IE;
                break;
              }

            if (h != NULL)
              {
                h->got.refcount += 1;
                old_got_type = elf_ve_hash_entry(h)->got_type;
              }
            else
              {
                bfd_signed_vma *local_got_refcounts;

                /* This is a global offset table entry for a local symbol. */
                local_got_refcounts = elf_local_got_refcounts(abfd);
                if (local_got_refcounts == NULL)
                  {
                    bfd_size_type size;

                    size = symtab_hdr->sh_info;
                    size *= sizeof (bfd_signed_vma)
                            + sizeof (bfd_vma) + sizeof (char);
                    local_got_refcounts = ((bfd_signed_vma *)
                                            bfd_zalloc (abfd, size));
                    if (local_got_refcounts == NULL)
                      return FALSE;
                    elf_local_got_refcounts (abfd) = local_got_refcounts;
                    elf_ve_local_tlsdesc_gotent(abfd)
                      = (bfd_vma *)(local_got_refcounts + symtab_hdr->sh_info);
                    elf_ve_local_got_tls_type(abfd)
                      = (char *)(local_got_refcounts + 2 * symtab_hdr->sh_info);
                  }
                local_got_refcounts[r_symndx] += 1;
                old_got_type = elf_ve_local_got_tls_type(abfd)[r_symndx];
              }

            /* If a TLS symbol is accessed using IE at least once,
               there is no point to use dynamic model for it. */
            if (old_got_type != got_type && old_got_type != GOT_UNKNOWN
                && (old_got_type != GOT_TLS_GD || got_type != GOT_TLS_IE))
              {
                if (old_got_type == GOT_TLS_IE && got_type == GOT_TLS_GD)
                  got_type = old_got_type;
                else
                  {
                    if (h)
                      name = h->root.root.string;
                    else
                      name = bfd_elf_sym_name(abfd, symtab_hdr, isym, NULL);

                    (*_bfd_error_handler)
                      (_("%B: '%s' accessed both as normal and thread local symbol"),
                       abfd, name);
                    bfd_set_error(bfd_error_bad_value);
                    return FALSE;
                  }
              }

            if (old_got_type != got_type)
              {
                if (h != NULL)
                  elf_ve_hash_entry(h)->got_type = got_type;
                else
                  elf_ve_local_got_tls_type(abfd)[r_symndx] = got_type;
              }
          }
        /* Fall through */

        case R_VE_GOTOFF32:
        case R_VE_GOTOFF_HI32:
        case R_VE_GOTOFF_LO32:
        create_got:
          if (htab->root.sgot == NULL)
            {
              if (htab->root.dynobj == NULL)
                htab->root.dynobj = abfd;
              if (!_bfd_elf_create_got_section(htab->root.dynobj, info))
                return FALSE;
            }
          break;

        case R_VE_PLT32:
        case R_VE_PLT_HI32:
        case R_VE_PLT_LO32:
          if (h == NULL)
            continue;

          h->needs_plt = 1;
          h->plt.refcount += 1;
          break;

        case R_VE_REFQUAD:
        case R_VE_REFLONG:
        case R_VE_HI32:
        case R_VE_LO32:
        case R_VE_SREL32:
        case R_VE_PC_HI32:
        case R_VE_PC_LO32:
          if (h != NULL && bfd_link_executable(info))
            {
              h->non_got_ref = 1;

              h->plt.refcount += 1;
              /* h->pointer_equality_needed = 1; */
            }

          size_reloc = FALSE;

// do_size:
          if ((bfd_link_pic(info)
               && (sec->flags & SEC_ALLOC) != 0
               && (!IS_VE_PCREL_TYPE(r_type)
                   || (h != NULL
                       && (!SYMBOLIC_BIND(info, h)
                           || h->root.type == bfd_link_hash_defweak
                           || !h->def_regular))))
              || (ELIMINATE_COPY_RELOCS
                  && !bfd_link_pic(info)
                  && (sec->flags & SEC_ALLOC) != 0
                  && h != NULL
                  && (h->root.type == bfd_link_hash_defweak
                      || !h->def_regular)))
            {
              struct elf_dyn_relocs *p;
              struct elf_dyn_relocs **head;

              if (sreloc == NULL)
                {
                  if (htab->root.dynobj == NULL)
                    htab->root.dynobj = abfd;

                  sreloc = _bfd_elf_make_dynamic_reloc_section
                             (sec, htab->root.dynobj, 3, abfd, /*rela?*/TRUE);

                  if (sreloc == NULL)
                    return FALSE;
                }

              /* If this is a global symbol, we count the number of relocations
                 we need for this symbol. */
              if (h != NULL)
                {
                  head = &((struct elf_ve_link_hash_entry *)h)->dyn_relocs;
                }
              else
                {
                  asection *s;
                  void **vpp;

                  isym = bfd_sym_from_r_symndx(&htab->sym_cache,
                                               abfd, r_symndx);
                  if (isym == NULL)
                    return FALSE;

                  s = bfd_section_from_elf_index(abfd, isym->st_shndx);
                  if (s == NULL)
                    s = sec;

                  vpp = &(elf_section_data(s)->local_dynrel);
                  head = (struct elf_dyn_relocs **)vpp;
                }

              p = *head;
              if (p == NULL || p->sec != sec)
                {
                  bfd_size_type amt = sizeof(*p);

                  p = ((struct elf_dyn_relocs*)bfd_alloc(htab->root.dynobj,
                                                         amt));
                  if (p == NULL)
                    return FALSE;
                  p->next = *head;
                  *head = p;
                  p->sec = sec;
                  p->count = 0;
                  p->pc_count = 0;
                }

              p->count += 1;
              if (IS_VE_PCREL_TYPE(r_type) || size_reloc)
                p->pc_count += 1;
            }
          break;

        default:
          break;
        }
    }

  return TRUE;
}

/* Adjust a symbol define by a dynamic object and referenced by a regular
   object. The current definition is in some section of the dynamic object,
   but we're not including those sections. We have to change the definition
   to something the rest of the link can understand. */
static bfd_boolean
elf_ve_adjust_dynamic_symbol(struct bfd_link_info *info,
                                 struct elf_link_hash_entry *h)
{
  struct elf_ve_link_hash_table *htab;
  asection *s;
  struct elf_ve_link_hash_entry *eh;
  struct elf_dyn_relocs *p;

  /* STT_GNU_IFUNC symbol must go through PLT. */
  if (h->type == STT_GNU_IFUNC)
    {
      if (h->ref_regular && SYMBOL_CALLS_LOCAL(info, h))
        {
          bfd_size_type pc_count = 0, count = 0;
          struct elf_dyn_relocs **pp;

          eh = (struct elf_ve_link_hash_entry *)h;
          for (pp = &eh->dyn_relocs; (p = *pp) != NULL; )
            {
              pc_count += p->pc_count;
              p->count -= p->pc_count;
              p->pc_count = 0;
              count += p->count;
              if (p->count == 0)
                *pp = p->next;
              else
                pp = &p->next;
            }

          if (pc_count || count)
            {
              h->needs_plt = 1;
              h->non_got_ref = 1;
              if (h->plt.refcount <= 0)
                h->plt.refcount = 1;
              else
                h->plt.refcount += 1;
            }
        }

      if (h->plt.refcount <= 0)
        {
          h->plt.offset = (bfd_vma)-1;
          h->needs_plt = 0;
        }
      return TRUE;
    }

  /* If this is a function, put it in the procedure linkage table.
     We will fill in the contents of the procedure linkage table later,
     when we know the address of the .got section. */
  if (h->type == STT_FUNC || h->needs_plt)
    {
      if (h->plt.refcount <= 0
          || SYMBOL_CALLS_LOCAL(info, h)
          || (ELF_ST_VISIBILITY(h->other) != STV_DEFAULT
              && h->root.type == bfd_link_hash_undefweak))
        {
          h->plt.offset = (bfd_vma)-1;
          h->needs_plt = 0;
        }

      return TRUE;
    }
  else
    h->plt.offset = (bfd_vma)-1;

  /* If this is a weak symbol, and there is a real definition, the
     processor independent code will have arranged for us to see the real
     definition first, and we can just use the same value. */
  if (h->u.weakdef != NULL)
    {
      h->root.u.def.section = h->u.weakdef->root.u.def.section;
      h->root.u.def.value = h->u.weakdef->root.u.def.value;
      if (ELIMINATE_COPY_RELOCS || info->nocopyreloc)
        h->non_got_ref = h->u.weakdef->non_got_ref;
      return TRUE;
    }

  /* This is a reference to a symbol defined by a dynamic object which is
     not a function. */
  if (bfd_link_pic(info))
    return TRUE;

  if (!h->non_got_ref)
    return TRUE;

  if (info->nocopyreloc)
    {
      h->non_got_ref = 0;
      return TRUE;
    }

  if (ELIMINATE_COPY_RELOCS)
    {
      eh = (struct elf_ve_link_hash_entry *)h;
      for (p = eh->dyn_relocs; p != NULL; p = p->next)
        {
          s = p->sec->output_section;
          if (s != NULL && (s->flags & SEC_READONLY) != 0)
            break;
        }

      if (p == NULL)
        {
          h->non_got_ref = 0;
          return TRUE;
        }
    }

  /* We must allocate the symbol in our .dynbss section, which will become
     part of the .bss section of the executable. */
  htab = elf_ve_hash_table(info);
  if (htab == NULL)
    return FALSE;

  /* We must generate a R_VE_COPY reloc to tell the dynamic linker to
     to copy the initial value out of the dynamic object and into the
     runtime process image. */
  if ((h->root.u.def.section->flags & SEC_ALLOC) != 0 && h->size != 0)
    {
      const struct elf_backend_data *bed;
      bed = get_elf_backend_data(info->output_bfd);
      htab->srelbss->size += bed->s->sizeof_rela;
      h->needs_copy = 1;
    }

  s = htab->sdynbss;

  return _bfd_elf_adjust_dynamic_copy(info, h, s);
}

/* Allocate space in .plt, .got and associated reloc sections for dynamic
   relocs. */
static bfd_boolean
elf_ve_allocate_dynrelocs(struct elf_link_hash_entry *h, void *inf)
{
  struct bfd_link_info *info;
  struct elf_ve_link_hash_table *htab;
  struct elf_ve_link_hash_entry *eh;
  struct elf_dyn_relocs *p;
  const struct elf_backend_data *bed;
  unsigned int plt_entry_size;

  if (h->root.type == bfd_link_hash_indirect)
    return TRUE;

  eh = (struct elf_ve_link_hash_entry *)h;
  info = (struct bfd_link_info *)inf;
  htab = elf_ve_hash_table(info);
  if (htab == NULL)
    return FALSE;
  bed = get_elf_backend_data(info->output_bfd);
  // plt_entry_size = GET_PLT_ENTRY_SIZE(info->output_bfd);
  plt_entry_size = htab->plt_entry_size;

  /* Since STT_GNU_IFUNC symbol must go through PLT, we handle it here
     if it is defined and referenced in a non-shared object. */
  if (h->type == STT_GNU_IFUNC && h->def_regular)
    return _bfd_elf_allocate_ifunc_dyn_relocs(info, h, &eh->dyn_relocs,
					      NULL,
                                              plt_entry_size, plt_entry_size,
                                              GOT_ENTRY_SIZE,
					      FALSE);
  else if (htab->root.dynamic_sections_created && h->plt.refcount > 0)
    {
      /* Make sure this symbol is output as a dynamic symbol. */
      if (h->dynindx == -1 && !h->forced_local)
        {
          if (!bfd_elf_link_record_dynamic_symbol(info, h))
            return FALSE;
        }

      if (bfd_link_pic(info) || WILL_CALL_FINISH_DYNAMIC_SYMBOL(1, 0, h))
        {
          asection *s = htab->root.splt;

          /* If this is the first .plt entry, make room for the special
             first entry. */
          if (s->size == 0)
            s->size += plt_entry_size;

          h->plt.offset = s->size;

          if (!bfd_link_pic(info) && !h->def_regular)
            {
              h->root.u.def.section = s;
              h->root.u.def.value = h->plt.offset;
            }

          /* Make room for this entry. */
          s->size += plt_entry_size;

          /* We also need to make an entry in the .got.plt section, which will
             be placed in the .got section by the linker script. */
          htab->root.sgotplt->size += GOT_ENTRY_SIZE;

          /* We also need to make an entry in the .rela.plt section. */
          htab->root.srelplt->size += bed->s->sizeof_rela;
          htab->root.srelplt->reloc_count++;
        }
      else
        {
          h->plt.offset = (bfd_vma)-1;
          h->needs_plt = 0;
        }
    }
  else
    {
      h->plt.offset = (bfd_vma)-1;
      h->needs_plt = 0;
    }

  eh->tlsdesc_got = (bfd_vma)-1;

  /* TODO - XXX  */
  if (h->got.refcount > 0 && bfd_link_executable(info) && h->dynindx == -1 
      && elf_ve_hash_entry(h)->got_type == GOT_TLS_IE)
    {
      h->got.offset = (bfd_vma) -1;
    }
  else if (h->got.refcount > 0)
    {
      asection *s;
      bfd_boolean dyn;
      int got_type = elf_ve_hash_entry(h)->got_type;

      if (h->dynindx == -1 && !h->forced_local)
        {
          if (!bfd_elf_link_record_dynamic_symbol(info, h))
            return FALSE;
        }

      /* TODO */
      htab->root.sgotplt->size += 2 * GOT_ENTRY_SIZE;
      h->got.offset = (bfd_vma) -2;

      {
        s = htab->root.sgot;
        h->got.offset = s->size;
        s->size += GOT_ENTRY_SIZE;
        if (got_type == GOT_TLS_GD)
          s->size += GOT_ENTRY_SIZE;
      }

      dyn = htab->root.dynamic_sections_created;
      /* R_VE_TLS_GD needs one dynamic reloc if local and two if global */
      if ((got_type == GOT_TLS_GD && h->dynindx == -1)
          || got_type == GOT_TLS_IE)
        htab->root.srelgot->size += 2 * bed->s->sizeof_rela;
      else if (got_type == GOT_TLS_GD)
        htab->root.srelgot->size += 2 * bed->s->sizeof_rela;
      else if ((ELF_ST_VISIBILITY(h->other) == STV_DEFAULT
           || h->root.type != bfd_link_hash_undefweak)
          && (bfd_link_pic(info)
              || WILL_CALL_FINISH_DYNAMIC_SYMBOL(dyn, 0, h)))
        htab->root.srelgot->size += bed->s->sizeof_rela;
    }
  else
    h->got.offset = (bfd_vma)-1;

  if (eh->dyn_relocs == NULL)
    return TRUE;

  if (bfd_link_pic(info))
    {
      if (SYMBOL_CALLS_LOCAL(info, h))
        {
          struct elf_dyn_relocs **pp;

          for (pp = &eh->dyn_relocs; (p = *pp) != NULL; )
            {
              p->count -= p->pc_count;
              p->pc_count = 0;
              if (p->count == 0)
                *pp = p->next;
              else
                pp = &p->next;
            }
        }

      if (eh->dyn_relocs != NULL && h->root.type == bfd_link_hash_undefweak)
        {
          if (ELF_ST_VISIBILITY(h->other) != STV_DEFAULT)
            eh->dyn_relocs = NULL;

          else if (h->dynindx == -1
                   && !h->forced_local
                   && !bfd_elf_link_record_dynamic_symbol(info, h))
            return FALSE;
        }
    }
  else if (ELIMINATE_COPY_RELOCS)
    {
      if (!h->non_got_ref
          && ((h->def_dynamic && !h->def_regular)
              || (htab->root.dynamic_sections_created
                  && (h->root.type == bfd_link_hash_undefweak
                      || h->root.type == bfd_link_hash_undefined))))
        {
          if (h->dynindx == -1
              && !h->forced_local
              && !bfd_elf_link_record_dynamic_symbol(info, h))
            return FALSE;

          if (h->dynindx != -1)
            goto keep;
        }

      eh->dyn_relocs = NULL;

    keep: ;
    }

  /* Finally, allocate space. */
  for (p = eh->dyn_relocs; p != NULL; p = p->next)
    {
      asection *sreloc;

      sreloc = elf_section_data(p->sec)->sreloc;
      sreloc->size += p->count * bed->s->sizeof_rela;
    }

  return TRUE;
}

static bfd_boolean
elf_ve_allocate_local_dynrelocs(void **slot, void *inf)
{
  struct elf_link_hash_entry *h = (struct elf_link_hash_entry *)*slot;

  if (h->type != STT_GNU_IFUNC
      || !h->def_regular
      || !h->ref_regular
      || !h->forced_local
      || h->root.type != bfd_link_hash_defined)
    abort();

  return elf_ve_allocate_dynrelocs(h, inf);
}

static bfd_boolean
elf_ve_readonly_dynrelocs(struct elf_link_hash_entry *h, void *inf)
{
  struct elf_ve_link_hash_entry *eh;
  struct elf_dyn_relocs *p;

  /* Skip local IFUNC symbols. */
  if (h->forced_local && h->type == STT_GNU_IFUNC)
    return TRUE;

  eh = (struct elf_ve_link_hash_entry *)h;
  for (p = eh->dyn_relocs; p != NULL; p = p->next)
    {
      asection *s = p->sec->output_section;

      if (s != NULL && (s->flags & SEC_READONLY) != 0)
        {
          struct bfd_link_info *info = (struct bfd_link_info *)inf;

          info->flags |= DF_TEXTREL;

          if (info->warn_shared_textrel && bfd_link_pic(info))
            info->callbacks->einfo(_("%P: %B: warning: relocation against `%s'"
                                     "in readonly section `%A'.\n"),
                                   p->sec->owner, h->root.root.string, p->sec);
          return FALSE;
        }
    }
  return TRUE;
}

/* Set the sizes of the dynamic sections. */
static bfd_boolean
elf_ve_size_dynamic_sections(bfd *output_bfd, struct bfd_link_info *info)
{
  struct elf_ve_link_hash_table *htab;
  bfd *dynobj;
  asection *s;
  bfd_boolean relocs;
  bfd *ibfd;
  const struct elf_backend_data *bed;

  htab = elf_ve_hash_table(info);
  if (htab == NULL)
    return FALSE;
  bed = get_elf_backend_data(output_bfd);

  dynobj = htab->root.dynobj;
  if (dynobj == NULL)
    abort();

  if (htab->root.dynamic_sections_created)
    {
      /* Set the contents of the .interp section to the interpreter. */
      if (bfd_link_executable(info) && !info->nointerp)
        {
          s = bfd_get_linker_section(dynobj, ".interp");
          if (s == NULL)
            abort();
          s->size = sizeof(ELF_DYNAMIC_INTERPRETER);
          s->contents = (unsigned char *)ELF_DYNAMIC_INTERPRETER;
        }
    }

  /* Set up .got offsets for local syms, and space for local dynamic relocs. */
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link.next)
    {
      bfd_signed_vma *local_got;
      bfd_signed_vma *end_local_got;
      char *local_got_type;
      bfd_vma *local_tlsdesc_gotent;
      bfd_size_type locsymcount;
      Elf_Internal_Shdr *symtab_hdr;
      asection *srel;

      for (s = ibfd->sections; s != NULL; s = s->next)
        {
          struct elf_dyn_relocs *p;

          for (p = (struct elf_dyn_relocs *)(elf_section_data(s)->local_dynrel);
               p != NULL;
               p = p->next)
            {
              if (!bfd_is_abs_section(p->sec)
                  && bfd_is_abs_section(p->sec->output_section))
                {
                  /* Input section has been discarded, either because it is
                     a copy of a linkcore section or due to linker script
                     /DISCARD/, so we'll be discarding the relocs too. */
                }
              else if (p->count != 0)
                {
                  srel = elf_section_data(p->sec)->sreloc;
                  srel->size += p->count * bed->s->sizeof_rela;
                  if ((p->sec->output_section->flags & SEC_READONLY) != 0
                      && (info->flags & DF_TEXTREL) == 0)
                    {
                      info->flags |= DF_TEXTREL;
                      if (info->warn_shared_textrel && bfd_link_pic(info))
                        info->callbacks->einfo(_("%P: %B: warning: relocation in readonly section `%A'.\n"),
                                               p->sec->owner, p->sec);
                    }
                }
            }
        }

      local_got = elf_local_got_refcounts(ibfd);
      if (!local_got)
        continue;

      symtab_hdr = &elf_symtab_hdr(ibfd);
      locsymcount = symtab_hdr->sh_info;
      end_local_got = local_got + locsymcount;
      local_got_type = elf_ve_local_got_tls_type(ibfd);
      local_tlsdesc_gotent = elf_ve_local_tlsdesc_gotent(ibfd);
      s = htab->root.sgot;
      srel = htab->root.srelgot;
      for (; local_got < end_local_got;
           ++local_got, ++local_got_type, ++local_tlsdesc_gotent)
        {
          *local_tlsdesc_gotent = (bfd_vma) -1;
          if (*local_got > 0)
            {
              /* TODO */
              if (*local_got_type == GOT_TLS_GD)
                {
                  *local_got = s->size;
                  s->size += GOT_ENTRY_SIZE;
                  s->size += GOT_ENTRY_SIZE;
                }
              if (bfd_link_pic(info) || *local_got_type == GOT_TLS_GD)
                {
                  /* TODO */
                  srel->size += bed->s->sizeof_rela;
                }
            }
          else
            *local_got = (bfd_vma)-1;
        }
    }

  if (htab->tls_ld_got.refcount > 0)
    {
      /* Allocate 2 got entries and 1 dynamic reloc for R_VE_TLS_GD_*
         relocs. */
      htab->tls_ld_got.offset = htab->root.sgot->size;
      htab->root.sgot->size += 2 * GOT_ENTRY_SIZE;
      htab->root.srelgot->size += bed->s->sizeof_rela;
    }
  else
    htab->tls_ld_got.offset = -1;

  /* Allocate global sym .plt and .got entries, and spece for global sym
     dynamic relocs. */
  elf_link_hash_traverse(&htab->root, elf_ve_allocate_dynrelocs, info);

  /* Allocate .plt and .got entries, and space for local symbols. */
  htab_traverse(htab->loc_hash_table, elf_ve_allocate_local_dynrelocs,
                info);

  /* For every jump slot reserved in the sgotplt, reloc_count is incremented. */
  if (htab->root.srelplt)
    {
      htab->sgotplt_jump_table_size
        = htab->root.srelplt->reloc_count * GOT_ENTRY_SIZE;
      htab->next_irelative_index = htab->root.srelplt->reloc_count - 1;
    }
  else if (htab->root.irelplt)
    htab->next_irelative_index = htab->root.irelplt->reloc_count - 1;

  /* TODO */

  if (htab->root.sgotplt)
    {
      /* Don't allocate .got.plt section if there are no GOT nor PLT entries
         and there is no reference to _GLOBAL_OFFSET_TABLE_. */
      if ((htab->root.hgot == NULL || !htab->root.hgot->ref_regular_nonweak)
          && (htab->root.sgotplt->size
              == get_elf_backend_data (output_bfd)->got_header_size)
          && (htab->root.splt == NULL
              || htab->root.splt->size == 0)
          && (htab->root.sgot == NULL
              || htab->root.sgot->size == 0)
          && (htab->root.iplt == NULL
              || htab->root.iplt->size == 0)
          && (htab->root.igotplt == NULL
              || htab->root.igotplt->size == 0))
        htab->root.sgotplt->size = 0;
    }

  /* TODO */

  /* We now have determined the sizes of the various dynamic sections. */
  relocs = FALSE;
  for (s = dynobj->sections; s != NULL; s = s->next)
    {
      if ((s->flags & SEC_LINKER_CREATED) == 0)
        continue;

      if (s == htab->root.splt
          || s == htab->root.sgot
          || s == htab->root.sgotplt
          || s == htab->root.iplt
          || s == htab->root.igotplt
          || s == htab->sdynbss)
        {
          /* Strip this section if we don't need it; */
        }
      else if (CONST_STRNEQ (bfd_get_section_name (dynobj, s), ".rela"))
        {
          if (s->size != 0 && s != htab->root.srelplt)
            relocs = TRUE;

          /* We use the reloc_count field as a counter if we need to copy
             relocs into the output file. */
          if (s != htab->root.srelplt)
            s->reloc_count = 0;
        }
      else
        {
          /* It's not one of our sections, do don't allocate space. */
          continue;
        }

      if (s->size == 0)
        {
          s->flags |= SEC_EXCLUDE;
          continue;
        }

      if ((s->flags & SEC_HAS_CONTENTS) == 0)
        continue;

      s->contents = (bfd_byte *) bfd_zalloc (dynobj, s->size);
      if (s->contents == NULL)
        return FALSE;
    }

  /* TODO */

  if (htab->root.dynamic_sections_created)
    {
      /* Add some entries to the .dynamic section. */
      if (bfd_link_executable(info))
        {
          if (!_bfd_elf_add_dynamic_entry(info, DT_DEBUG, 0))
            return FALSE;
        }

      if (htab->root.splt->size != 0)
        {
          if (!_bfd_elf_add_dynamic_entry(info, DT_PLTGOT, 0)
              || !_bfd_elf_add_dynamic_entry(info, DT_PLTRELSZ, 0)
              || !_bfd_elf_add_dynamic_entry(info, DT_PLTREL, DT_RELA)
              || !_bfd_elf_add_dynamic_entry(info, DT_JMPREL, 0))
            return FALSE;

          /* TODO */
        }

      if (relocs)
        {
          if (!_bfd_elf_add_dynamic_entry(info, DT_RELA, 0)
              || !_bfd_elf_add_dynamic_entry(info, DT_RELASZ, 0)
              || !_bfd_elf_add_dynamic_entry(info, DT_RELAENT,
                                             bed->s->sizeof_rela))
            return FALSE;

          /* If any dynamic relocs apply to a readonly section,
             then we need a DT_TEXTREL entry. */
          if ((info->flags & DF_TEXTREL) == 0)
            elf_link_hash_traverse (&htab->root,
                                    elf_ve_readonly_dynrelocs, info);

          if ((info->flags & DT_TEXTREL) != 0)
            {
              if (!_bfd_elf_add_dynamic_entry(info, DT_TEXTREL, 0))
                return FALSE;
            }
        }
    }

  return TRUE;
}

static bfd_boolean
elf_ve_always_size_sections(bfd *output_bfd ATTRIBUTE_UNUSED,
                                 struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  /* TODO */

  return TRUE;
}

static bfd_vma
elf_ve_dtpoff_base(struct bfd_link_info *info)
{
  if (elf_hash_table(info)->tls_sec == NULL)
    return 0;
  return elf_hash_table(info)->tls_sec->vma;
}

static bfd_vma
elf_ve_tpoff(struct bfd_link_info *info, bfd_vma address)
{
  struct elf_link_hash_table *htab = elf_hash_table(info);
  const struct elf_backend_data *bed = get_elf_backend_data(info->output_bfd);
  bfd_vma static_tls_size;

  if (htab->tls_sec == NULL)
    return 0;

  static_tls_size = BFD_ALIGN(htab->tls_size, bed->static_tls_alignment);
  static_tls_size = 0;  /* FIXME */
  return TCB_OFFSET + address - static_tls_size - htab->tls_sec->vma;
}

/* Relocate an VE ELF section. */
static bfd_boolean
elf_ve_relocate_section(bfd *output_bfd,
                            struct bfd_link_info *info,
                            bfd *input_bfd,
                            asection *input_section,
                            bfd_byte *contents,
                            Elf_Internal_Rela *relocs,
                            Elf_Internal_Sym *local_syms,
                            asection **local_sections)
{
  struct elf_ve_link_hash_table *htab;
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  bfd_vma *local_got_offsets;
  bfd_vma *local_tlsdesc_gotents ATTRIBUTE_UNUSED;
  Elf_Internal_Rela *rel;
  Elf_Internal_Rela *relend;
  unsigned int plt_entry_size;

  htab = elf_ve_hash_table(info);
  if (htab == NULL)
    return FALSE;
  plt_entry_size = htab->plt_entry_size;
  symtab_hdr = &elf_symtab_hdr(input_bfd);
  sym_hashes = elf_sym_hashes(input_bfd);
  local_got_offsets = elf_local_got_offsets(input_bfd);
  local_tlsdesc_gotents = elf_ve_local_tlsdesc_gotent(input_bfd);

  /* TODO */

  rel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; rel++)
    {
      unsigned int r_type;
      reloc_howto_type *howto;
      unsigned long r_symndx;
      struct elf_link_hash_entry *h;
      Elf_Internal_Sym *sym;
      asection *sec;
      bfd_vma off /* , offplt */;
      bfd_vma relocation;
      bfd_boolean unresolved_reloc;
      bfd_reloc_status_type r;
      int got_type;
      asection *base_got;
      bfd_vma st_size ATTRIBUTE_UNUSED;

      r_type = ELF64_R_TYPE(rel->r_info);
      howto = elf_ve_howto_from_type(r_type);
      r_symndx = ELF64_R_SYM(rel->r_info);
      h = NULL;
      sym = NULL;
      sec = NULL;
      unresolved_reloc = FALSE;
      if (r_symndx < symtab_hdr->sh_info)
        {
          sym = local_syms + r_symndx;
          sec = local_sections[r_symndx];

          relocation = _bfd_elf_rela_local_sym(output_bfd, sym, &sec, rel);
          st_size = sym->st_size;

          /* Relocate against local STT_GNU_IFUNC symbol. */
          if (!bfd_link_relocatable(info)
              && ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC)
            {
              h = elf_ve_get_local_sym_hash(htab, input_bfd, rel, FALSE);
              if (h == NULL)
                abort();

              /* Set STT_GNU_IFUNC symbol value. */
              h->root.u.def.value = sym->st_value;
              h->root.u.def.section = sec;
            }
        }
      else
        {
          bfd_boolean warned ATTRIBUTE_UNUSED;
          bfd_boolean ignored ATTRIBUTE_UNUSED;

          RELOC_FOR_GLOBAL_SYMBOL(info, input_bfd, input_section, rel,
                                  r_symndx, symtab_hdr, sym_hashes, h, sec,
                                  relocation, unresolved_reloc, warned, ignored);
          st_size = h->size;
        }

      if (sec != NULL && discarded_section(sec))
        RELOC_AGAINST_DISCARDED_SECTION(info, input_bfd, input_section, rel,
                                        1, relend, howto, 0, contents);

      if (bfd_link_relocatable(info))
        continue;

      /* Since STT_GNU_IFUNC symbol must go through PLT. */
      if (h != NULL && h->type == STT_GNU_IFUNC && h->def_regular)
        {
          asection *plt;
          // bfd_vma plt_index;
          const char *name;

          if ((input_section->flags & SEC_ALLOC) == 0
              || h->plt.offset == (bfd_vma)-1)
            abort();

          /* STT_GNU_IFUNC symbol must go through PLT. */
          plt = htab->root.splt ? htab->root.splt : htab->root.iplt;
          relocation = (plt->output_section->vma
                        + plt->output_offset + h->plt.offset);

          switch (r_type)
            {
            default:
              if (h->root.root.string)
                name = h->root.root.string;
              else
                name = bfd_elf_sym_name(input_bfd, symtab_hdr, sym, NULL);
              (*_bfd_error_handler)
                (_("%B: relocation %s against STT_GNU_IFUNC symbol `%s' "
                   "isn't handled by %s"), input_bfd,
                elf64_ve_howto_table[r_type].name, name, __FUNCTION__);
              bfd_set_error(bfd_error_bad_value);
              return FALSE;

            case R_VE_REFQUAD:
            case R_VE_HI32:
            case R_VE_LO32:
              if (rel->r_addend != 0)
                {
                  if (h->root.root.string)
                    name = h->root.root.string;
                  else
                    name = bfd_elf_sym_name(input_bfd, symtab_hdr, sym, NULL);
                  (*_bfd_error_handler)
                    (_("%B: relocation %s against STT_GNU_IFUNC symbol `%s' "
                       "has non-zero addend: %d"), input_bfd,
                       elf64_ve_howto_table[r_type].name, name,
                       rel->r_addend);
                  bfd_set_error(bfd_error_bad_value);
                  return FALSE;
                }

              /* Generate dynamic relocation only when there is a non-GOT
                 reference in a shared object. */
              if (bfd_link_pic(info) && h->non_got_ref)
                {
                  Elf_Internal_Rela outrel;
                  asection *sreloc;

                  /* Need a dynamic relocation to get the real function addr. */
                  outrel.r_offset = _bfd_elf_section_offset(output_bfd,
                                                            info,
                                                            input_section,
                                                            rel->r_offset);
                  if (outrel.r_offset == (bfd_vma)-1
                      || outrel.r_offset == (bfd_vma)-2)
                    abort();

                  outrel.r_offset += (input_section->output_section->vma
                                      + input_section->output_offset);

                  if (h->dynindx == -1 || h->forced_local || bfd_link_executable(info))
                    {
                      /* This symbol is resolved locally. */
                      outrel.r_info = ELF64_R_INFO(0, R_VE_IRELATIVE);
                      outrel.r_addend = (h->root.u.def.value
                                         + h->root.u.def.section->output_section->vma
                                         + h->root.u.def.section->output_offset);
                    }
                  else
                    {
                      outrel.r_info = ELF64_R_INFO(h->dynindx, r_type);
                      outrel.r_addend = 0;
                    }

                  sreloc = htab->root.irelifunc;
                  elf_append_rela(output_bfd, sreloc, &outrel);

                  continue;
                }
              /* FALLTHROUGH */
            case R_VE_SREL32:
            case R_VE_PC_HI32:
            case R_VE_PC_LO32:
            case R_VE_PLT32:
            case R_VE_PLT_HI32:
            case R_VE_PLT_LO32:
              goto do_relocation;
            }
        }

      /* When generating a shared object, the relocations handled here are
         copied into the output file to be resolved at run time. */
      switch (r_type)
        {
        case R_VE_GOT32:
        case R_VE_GOT_HI32:
        case R_VE_GOT_LO32:
          base_got = htab->root.sgot;

          if (htab->root.sgot == NULL)
            abort();

          if (h != NULL)
            {
              bfd_boolean dyn;

              off = h->got.offset;
              if (h->needs_plt
                  && h->plt.offset != (bfd_vma)-1 && off == (bfd_vma)-1)
                {
                  bfd_vma plt_index = h->plt.offset / plt_entry_size - 1;
                  off = (plt_index + 3) * GOT_ENTRY_SIZE;
                  base_got = htab->root.sgotplt;
                }

              dyn = htab->root.dynamic_sections_created;

              if (!WILL_CALL_FINISH_DYNAMIC_SYMBOL(dyn, bfd_link_pic(info), h)
                  || (bfd_link_pic(info) && SYMBOL_REFERENCES_LOCAL (info, h))
                  || (ELF_ST_VISIBILITY(h->other)
                      && h->root.type == bfd_link_hash_undefweak))
                {
                  if ((off & 1) != 0)
                    off &= ~1;
                  else
                    {
                      bfd_put_64(output_bfd, relocation,
                                 base_got->contents + off);
                      h->got.offset |= 1;
                    }
                }
              else
                unresolved_reloc = FALSE;
            }
          else
            {
              if (local_got_offsets == NULL)
                abort();

              off = local_got_offsets[r_symndx];

              if ((off & 1) != 0)
                off &= ~1;
              else
                {
                  bfd_put_64(output_bfd, relocation, base_got->contents + off);

                  if (bfd_link_pic(info))
                    {
                      asection *s;
                      Elf_Internal_Rela outrel;

                      s = htab->root.srelgot;
                      if (s == NULL)
                        abort();

                      outrel.r_offset = (base_got->output_section->vma
                                         + base_got->output_offset + off);
                      outrel.r_info = ELF64_R_INFO(0, R_VE_RELATIVE);
                      outrel.r_addend = relocation;
                      elf_append_rela(output_bfd, s, &outrel);
                    }

                  local_got_offsets[r_symndx] |= 1;
                }
            }

          if (off >= (bfd_vma)-2)
            abort();

          relocation = base_got->output_section->vma
                       + base_got->output_offset + off;
          /* TODO */
          relocation -= htab->root.sgotplt->output_section->vma
                        - htab->root.sgotplt->output_offset;
          break;

        case R_VE_GOTOFF32:
        case R_VE_GOTOFF_HI32:
        case R_VE_GOTOFF_LO32:
          if (!bfd_link_executable(info)
              && h
              && !SYMBOLIC_BIND(info, h)
              && h->def_regular
              && h->type == STT_FUNC
              && ELF_ST_VISIBILITY(h->other) == STV_PROTECTED)
            {
              (*_bfd_error_handler)
                (_("%B: relocation R_VE_GOTOFF* against pretected function `%s' can not be used when making a shared object"),
                input_bfd, h->root.root.string);
              bfd_set_error(bfd_error_bad_value);
              return FALSE;
            }

          relocation -= htab->root.sgotplt->output_section->vma
                        + htab->root.sgotplt->output_offset;
          break;

        case R_VE_PLT32:
        case R_VE_PLT_HI32:
        case R_VE_PLT_LO32:
          /* Relocation is to the entry for this symbol in the PLT. */
          if (h == NULL)
            break;

          if (h->plt.offset == (bfd_vma)-1 || htab->root.splt == NULL)
            {
              break;
            }

          relocation = (htab->root.splt->output_section->vma
                        + htab->root.splt->output_offset + h->plt.offset);
          unresolved_reloc = FALSE;
          break;

        case R_VE_SREL32:
        case R_VE_PC_HI32:
        case R_VE_PC_LO32:
          if (bfd_link_pic(info)
              && (input_section->flags & SEC_ALLOC) != 0
              && (input_section->flags & SEC_READONLY) != 0
              && h != NULL)
            {
              bfd_boolean fail = FALSE;
              bfd_boolean branch = (r_type == R_VE_SREL32);

              if (SYMBOL_REFERENCES_LOCAL(info, h))
                {
                  fail = !h->def_regular && !branch;
                }
              else
                {
                  /* Symbol isn't referenced locally. */
                  fail = (!branch
                          || ELF_ST_VISIBILITY(h->other) == STV_DEFAULT);
                }

              if (fail)
                {
                  const char *fmt;
                  const char *v;
                  const char *pic = "";

                  switch (ELF_ST_VISIBILITY(h->other))
                    {
                    case STV_HIDDEN:
                      v = _("hidden symbol");
                      break;
                    case STV_INTERNAL:
                      v = _("internal symbol");
                      break;
                    case STV_PROTECTED:
                      v = _("protected symbol");
                      break;
                    default:
                      v = _("symbol");
                      pic = _("; recompile with -fPIC");
                      break;
                    }

                  if (h->def_regular)
                    fmt = _("%B: relocation %s against %s `%s' can not be used when making a shared object%s");
                  else
                    fmt = _("%B: relocation %s against undefined %s `%s' can not be used when making a shared object%s");

                  (*_bfd_error_handler)(fmt, input_bfd,
                                        elf64_ve_howto_table[r_type].name,
                                        v, h->root.root.string, pic);
                  bfd_set_error(bfd_error_bad_value);
                  return FALSE;
                }
            }
          /* Fall through */

        case R_VE_REFQUAD:
        case R_VE_REFLONG:
        case R_VE_HI32:
        case R_VE_LO32:
          if ((input_section->flags & SEC_ALLOC) == 0)
            break;

          if ((bfd_link_pic(info)
               && (h == NULL
                   || ELF_ST_VISIBILITY(h->other) == STV_DEFAULT
                   || h->root.type != bfd_link_hash_undefweak)
               && (!IS_VE_PCREL_TYPE(r_type)
                   || !SYMBOL_CALLS_LOCAL(info, h)))
              || (ELIMINATE_COPY_RELOCS
                  && !bfd_link_pic(info)
                  && h != NULL
                  && h->dynindx != -1
                  && !h->non_got_ref
                  && ((h->def_dynamic && !h->def_regular)
                      || h->root.type == bfd_link_hash_undefweak
                      || h->root.type == bfd_link_hash_undefined)))
            {
              Elf_Internal_Rela outrel;
              bfd_boolean skip, relocate;
              asection *sreloc;

              skip = FALSE;
              relocate = FALSE;

              outrel.r_offset = _bfd_elf_section_offset(output_bfd, info,
                                                        input_section,
                                                        rel->r_offset);
              if (outrel.r_offset == (bfd_vma)-1)
                skip = TRUE;
              else if (outrel.r_offset == (bfd_vma)-2)
                skip = TRUE, relocate = TRUE;

              outrel.r_offset += (input_section->output_section->vma
                                  + input_section->output_offset);

              if (skip)
                memset(&outrel, 0, sizeof outrel);

              else if (h != NULL
                       && h->dynindx != -1
                       && (IS_VE_PCREL_TYPE(r_type)
                           || !bfd_link_pic(info)
                           || !SYMBOLIC_BIND(info, h)
                           || !h->def_regular))
                {
                  outrel.r_info = ELF64_R_INFO(h->dynindx, r_type);
                  outrel.r_addend = rel->r_addend;
                }
              else
                {
                  /* This symbol is local, or markded to become local. */
                  if (r_type == R_VE_REFQUAD || r_type == R_VE_REFLONG)
                    {
                      relocate = TRUE;
                      outrel.r_info = ELF64_R_INFO(0, R_VE_RELATIVE);
                      outrel.r_addend = relocation + rel->r_addend;
                    }
                  else
                    {
                      long sindx;

                      if (bfd_is_abs_section(sec))
                        sindx = 0;
                      else if (sec == NULL || sec->owner == NULL)
                        {
                          bfd_set_error(bfd_error_bad_value);
                          return FALSE;
                        }
                      else
                        {
                          asection *osec;

                          osec = sec->output_section;
                          sindx = elf_section_data(osec)->dynindx;
                          if (sindx == 0)
                            {
                              asection *oi = htab->root.text_index_section;
                              sindx = elf_section_data(oi)->dynindx;
                            }
                        }

                      outrel.r_info = ELF64_R_INFO(sindx, r_type);
                      outrel.r_addend = relocation + rel->r_addend;
                    }
                }

              sreloc = elf_section_data(input_section)->sreloc;

              if (sreloc == NULL || sreloc->contents == NULL)
                {
                  r = bfd_reloc_notsupported;
                  goto check_relocation_error;
                }

              elf_append_rela(output_bfd, sreloc, &outrel);

              if (!relocate)
                continue;
            }
          break;

        case R_VE_TLS_GD_HI32:
        case R_VE_TLS_GD_LO32:
          got_type = GOT_UNKNOWN;
          if (h == NULL && local_got_offsets)
            got_type = elf_ve_local_got_tls_type(input_bfd)[r_symndx];
          else if (h != NULL)
            got_type = elf_ve_hash_entry (h)->got_type;

          if (!elf_ve_tls_transition(info, input_bfd, input_section,
                                         contents, symtab_hdr, sym_hashes,
                                         &r_type, got_type, rel, relend,
                                         h, r_symndx))
            return FALSE;

          if (r_type == R_VE_TPOFF_HI32 || r_type == R_VE_TPOFF_LO32)
            {
              bfd_vma roff = rel->r_offset;

              if (ELF64_R_TYPE(rel->r_info) == R_VE_TLS_GD_LO32)
                {
                  /* GD->LE transision. Change
                       lea %s0,foo@TLS_GD_LO
                       and %s0,%s0,(32)0
                       lea.sl %s0,foo@TLS_GD_HI(%got,%s0)
                       lea %s12,__tls_get_addr@PLT_LO(-24)
                       and %s12,%s12,(32)0
                       sic %lr
                       lea.sl %s12,__tls_get_addr@PLT_HI(%s12,%lr)
                       bsic %lr,(,%s12)
                     into:
                       lea %s0,foo@TPOFF_LO
                       and %s0,%s0,(32)0
                       lea.sl %s0,foo@TPOFF_HI(%tp,%s0)
                       nop
                       nop
                       nop
                       nop
                       nop */
                  memcpy(contents + roff,      "\x30\0\0\0\0\0\0\x06", 8);
                  memcpy(contents + roff + 16, "\0\0\0\0\x80\x8e\x80\x06", 8);
                  memcpy(contents + roff + 24, "\0\0\0\0\0\0\0\x79", 8);
                  memcpy(contents + roff + 32, "\0\0\0\0\0\0\0\x79", 8);
                  memcpy(contents + roff + 40, "\0\0\0\0\0\0\0\x79", 8);
                  memcpy(contents + roff + 48, "\0\0\0\0\0\0\0\x79", 8);
                  memcpy(contents + roff + 56, "\0\0\0\0\0\0\0\x79", 8);

                  bfd_put_32(output_bfd,
                             (elf_ve_tpoff(info, relocation) << 32) >> 32,
                             contents + roff);
                  bfd_put_32(output_bfd,
                             elf_ve_tpoff(info, relocation) >> 32,
                             contents + roff + 16);

                  /* Skip R_VE_TLS_GD_HI/R_VE_PLT_LO/R_VE_PTL_HI */
                  rel += 3;
                  continue;
                }
            }

          if (htab->root.sgot == NULL)
            abort();

          if (h != NULL)
            {
              off = h->got.offset;
              /* offplt = elf_ve_hash_entry(h)->tlsdesc_got; */
            }
          else
            {
              if (local_got_offsets == NULL)
                abort();

              off = local_got_offsets[r_symndx];
              /* offplt = local_tlsdesc_gotents[r_symndx]; */
            }

          if ((off & 1) != 0)
            off &= ~1;
          else
            {
              Elf_Internal_Rela outrel;
              int dr_type, indx;
              asection *sreloc;

              if (htab->root.srelgot == NULL)
                abort();

              indx = h && h->dynindx != -1 ? h->dynindx : 0;

              sreloc = htab->root.srelgot;
              outrel.r_offset = (htab->root.sgot->output_section->vma
                                 + htab->root.sgot->output_offset + off);

              dr_type = R_VE_DTPMOD64;

              bfd_put_64(output_bfd, relocation,
                         htab->root.sgot->contents + off);
              outrel.r_addend = 0;
              outrel.r_info = ELF64_R_INFO(indx, dr_type);

              elf_append_rela(output_bfd, sreloc, &outrel);

              {
                if (indx == 0)
                  {
                    BFD_ASSERT(!unresolved_reloc);
                    bfd_put_64(output_bfd,
                               relocation - elf_ve_dtpoff_base(info),
                               htab->root.sgot->contents + off + GOT_ENTRY_SIZE);
                  }
                else
                  {
                    bfd_put_64(output_bfd, 0,
                               htab->root.sgot->contents + off + GOT_ENTRY_SIZE);
                    outrel.r_info = ELF64_R_INFO(indx, R_VE_DTPOFF64);
                    outrel.r_offset += GOT_ENTRY_SIZE;
                    elf_append_rela(output_bfd, sreloc, &outrel);
                  }
              }
//dr_done:
              if (h != NULL)
                h->got.offset |= 1;
              else
                local_got_offsets[r_symndx] |= 1;
          }

          if (r_type == ELF64_R_TYPE(rel->r_info))
            {
              relocation = htab->root.sgot->output_section->vma
                           + htab->root.sgot->output_offset + off;
              unresolved_reloc = FALSE;
            }
          break;

        default:
          break;
        }

      if (unresolved_reloc
          && !((input_section->flags & SEC_DEBUGGING) != 0
               && h->def_dynamic)
          && _bfd_elf_section_offset(output_bfd, info, input_section,
                                     rel->r_offset) != (bfd_vma)-1)
        {
          (*_bfd_error_handler)
            (_("%B(%A+0x%lx): unresolvable %s relocation against symbol `%s'"),
              input_bfd, input_section, (long) rel->r_offset, howto->name,
              h->root.root.string);
          return FALSE;
        }

do_relocation:
      r = _bfd_final_link_relocate(howto, input_bfd, input_section, contents,
                                   rel->r_offset, relocation, rel->r_addend);

check_relocation_error:
      if (r != bfd_reloc_ok)
        {
          const char *name;

          if (h != NULL)
            name = h->root.root.string;
          else
            {
              name = bfd_elf_string_from_elf_section(input_bfd,
                                                     symtab_hdr->sh_link,
                                                     sym->st_name);
              if (name == NULL)
                return FALSE;
              if (*name == '\0')
                name = bfd_section_name(input_bfd, sec);
            }

          if (r == bfd_reloc_overflow)
            {
              (*info->callbacks->reloc_overflow)
                    (info, (h ? &h->root : NULL), name, howto->name,
                    (bfd_vma) 0, input_bfd, input_section, rel->r_offset);
            }
          else
            {
              (*_bfd_error_handler)
                (_("%B(%A+0x%lx): reloc against `%s': error %d"),
                  input_bfd, input_section, (long)rel->r_offset, name, (int)r);
              return FALSE;
            }
        }
    }

  return TRUE;
}

static bfd_boolean
elf_ve_finish_dynamic_symbol(bfd *output_bfd,
                                 struct bfd_link_info *info,
                                 struct elf_link_hash_entry *h,
                                 Elf_Internal_Sym *sym)
{
  struct elf_ve_link_hash_table *htab;
  htab = elf_ve_hash_table(info);
  if (htab == NULL)
    return FALSE;

  if (h->plt.offset != (bfd_vma)-1)
    {
      bfd_vma plt_index;
      bfd_vma got_offset;
      Elf_Internal_Rela rela;
      bfd_byte *loc;
      asection *plt = NULL, *gotplt = NULL, *relplt = NULL;
      const struct elf_backend_data *bed;
      bfd_vma sym_addr = 0;

      /* This symbol has an entry in the PLT. */
      if (htab->root.splt != NULL)
        {
          plt = htab->root.splt;
          gotplt = htab->root.sgotplt;
          relplt = htab->root.srelplt;
        }

      if ((h->dynindx == -1
           && !((h->forced_local || bfd_link_executable(info))
                && h->def_regular
                && h->type == STT_GNU_IFUNC))
          || plt == NULL || gotplt == NULL || relplt == NULL)
        abort();

      /* Get the index in the procedure linkage table which corresponds
         to this symbol. */
      if (plt == htab->root.splt)
        {
          got_offset = h->plt.offset / htab->plt_entry_size - 1;
          got_offset = (got_offset + 3) * GOT_ENTRY_SIZE;
        }
      else
        {
          got_offset = h->plt.offset / htab->plt_entry_size;
          got_offset = got_offset * GOT_ENTRY_SIZE;
        }

      /* Fill in the entry in the procedure linkage table. */
      memcpy(plt->contents + h->plt.offset, elf_ve_plt_entry,
             htab->plt_entry_size);

      /* Insert the relocation positions of the PLT sections. */

      /* Put offset the instruction referring to the GOT entry */
      if (bfd_link_executable(info))
        {
          sym_addr = gotplt->output_section->vma + gotplt->output_offset
                     + got_offset;
          /* change "%got" -> "" (zero) */
          bfd_put_8(output_bfd, 0, plt->contents + h->plt.offset + 21);
        }
      else
        sym_addr = gotplt->output_section->vma + gotplt->output_offset
                   + got_offset
                   - (htab->root.sgotplt->output_section->vma
                      + htab->root.sgotplt->output_offset);
      bfd_put_32(output_bfd, sym_addr & 0xffffffff,
                 plt->contents + h->plt.offset);
      bfd_put_32(output_bfd, sym_addr >> 32,
                 plt->contents + h->plt.offset + htab->plt_got_offset);

      /* Fill in the entry in the GOT, initially this points to the last
         "lea" instruction in the PLT entry. */
      bfd_put_64(output_bfd, (plt->output_section->vma
                              + plt->output_offset
                              + h->plt.offset + htab->plt_lazy_offset),
                 gotplt->contents + got_offset);

      /* Fill in the entry in the .rela.plt section. */
      rela.r_offset = (gotplt->output_section->vma
                       + gotplt->output_offset
                       + got_offset);
      if (h->dynindx == -1
          || ((bfd_link_executable(info) || ELF_ST_VISIBILITY(h->other) != STV_DEFAULT)
              && h->def_regular
              && h->type == STT_GNU_IFUNC))
        {
          rela.r_info = ELF64_R_INFO(0, R_VE_IRELATIVE);
          rela.r_addend = (h->root.u.def.value
                             + h->root.u.def.section->output_section->vma
                             + h->root.u.def.section->output_offset);
          plt_index = htab->next_irelative_index--;
        }
      else
        {
          rela.r_info = ELF64_R_INFO(h->dynindx, R_VE_JUMP_SLOT);
          rela.r_addend = 0;
          plt_index = htab->next_jump_slot_index++;
        }

      /* Don't fill PLT entry for static executables. */
      if (plt == htab->root.splt)
        {
          /* Put relocation index. */
          bfd_put_32(output_bfd, plt_index,
                     plt->contents + h->plt.offset + htab->plt_lazy_offset);

          /* Put offset for branch .PLT0. */
          bfd_put_32(output_bfd, -(h->plt.offset + htab->plt_lazy_offset + 8),
                     plt->contents + h->plt.offset + htab->plt_plt_offset);
        }

      bed = get_elf_backend_data(output_bfd);
      loc = relplt->contents + plt_index * bed->s->sizeof_rela;
      bed->s->swap_reloca_out(output_bfd, &rela, loc);

      if (!h->def_regular)
        {
          sym->st_shndx = SHN_UNDEF;
          if (!h->pointer_equality_needed)
            sym->st_value = 0;
        }
    }

  if (h->got.offset != (bfd_vma)-1
      && elf_ve_hash_entry(h)->got_type == GOT_NORMAL
      && elf_ve_hash_entry(h)->got_type != GOT_TLS_IE)
    {
      Elf_Internal_Rela rela;

      /* This symbol has an entry in the GOT. */
      if (htab->root.sgot == NULL || htab->root.srelgot == NULL)
        abort();

      rela.r_offset = (htab->root.sgot->output_section->vma
                       + htab->root.sgot->output_offset
                       + (h->got.offset & ~(bfd_vma)1));

      if (h->def_regular && h->type == STT_GNU_IFUNC)
        {
          if (bfd_link_pic(info))
            {
              /* Generate R_VE_GLOB_DAT */
              goto do_glob_dat;
            }
          else
            {
              asection *plt;

              if (!h->pointer_equality_needed)
                abort();

              plt = htab->root.splt ? htab->root.splt : htab->root.iplt;
              bfd_put_64(output_bfd, (plt->output_section->vma
                                      + plt->output_offset
                                      + h->plt.offset),
                         htab->root.sgot->contents + h->got.offset);
              return TRUE;
            }
        }
      else if (bfd_link_pic(info) && SYMBOL_REFERENCES_LOCAL(info, h))
        {
          if (!h->def_regular)
            return FALSE;

          rela.r_info = ELF64_R_INFO(0, R_VE_RELATIVE);
          rela.r_addend = (h->root.u.def.value
                           + h->root.u.def.section->output_section->vma
                           + h->root.u.def.section->output_offset);
        }
      else
        {
do_glob_dat:
          bfd_put_64(output_bfd, (bfd_vma)0,
                     htab->root.sgot->contents + h->got.offset);
          rela.r_info = ELF64_R_INFO(h->dynindx, R_VE_GLOB_DAT);
          rela.r_addend = 0;
        }

      elf_append_rela(output_bfd, htab->root.srelgot, &rela);
    }

  if (h->needs_copy)
    {
      Elf_Internal_Rela rela;

      if (h->dynindx == -1
          || (h->root.type != bfd_link_hash_defined
              && h->root.type != bfd_link_hash_defweak)
          || htab->srelbss == NULL)
        abort();

      rela.r_offset = (h->root.u.def.value
                       + h->root.u.def.section->output_section->vma
                       + h->root.u.def.section->output_offset);
      rela.r_info = ELF64_R_INFO(h->dynindx, R_VE_COPY);
      rela.r_addend = 0;
      elf_append_rela(output_bfd, htab->srelbss, &rela);
    }

  if (sym != NULL
      && (h == elf_hash_table(info)->hdynamic
          || h == elf_hash_table(info)->hgot))
    sym->st_shndx = SHN_ABS;

  return TRUE;
}

static bfd_boolean
elf_ve_finish_local_dynamic_symbol(void **slot, void *inf)
{
  struct elf_link_hash_entry *h = (struct elf_link_hash_entry *)*slot;
  struct bfd_link_info *info = (struct bfd_link_info *)inf;

  return elf_ve_finish_dynamic_symbol(info->output_bfd, info, h, NULL);
}

static enum elf_reloc_type_class
elf_ve_reloc_type_class(const struct bfd_link_info *info ATTRIBUTE_UNUSED,
                            const asection *rel_sec ATTRIBUTE_UNUSED,
                            const Elf_Internal_Rela *rela)
{
  switch ((int)ELF64_R_TYPE(rela->r_info))
    {
    case R_VE_RELATIVE:
      return reloc_class_relative;
    case R_VE_JUMP_SLOT:
      return reloc_class_plt;
    case R_VE_COPY:
      return reloc_class_copy;
    default:
      return reloc_class_normal;
    }
}

/* Finish up the dynamic sections. */
static bfd_boolean
elf_ve_finish_dynamic_sections(bfd *output_bfd, struct bfd_link_info *info)
{
  struct elf_ve_link_hash_table *htab;
  bfd *dynobj;
  asection *sdyn;

  htab = elf_ve_hash_table(info);
  dynobj = htab->root.dynobj;
  sdyn = bfd_get_linker_section(dynobj, ".dynamic");

  if (htab->root.dynamic_sections_created)
    {
      Elf64_External_Dyn *dyncon, *dynconend;

      if (sdyn == NULL || htab->root.sgot == NULL)
        abort();

      dyncon = (Elf64_External_Dyn *)sdyn->contents;
      dynconend = (Elf64_External_Dyn *)(sdyn->contents + sdyn->size);
      for (; dyncon < dynconend; dyncon++)
        {
          Elf_Internal_Dyn dyn;
          asection *s;

          bfd_elf64_swap_dyn_in(dynobj, dyncon, &dyn);

          switch (dyn.d_tag)
            {
            default:
              continue;

            case DT_PLTGOT:
              s = htab->root.sgotplt;
              dyn.d_un.d_ptr = s->output_section->vma + s->output_offset;
              break;

            case DT_JMPREL:
              dyn.d_un.d_ptr = htab->root.srelplt->output_section->vma;
              break;

            case DT_PLTRELSZ:
              s = htab->root.srelplt->output_section;
              dyn.d_un.d_val = s->size;
              break;

            case DT_RELASZ:
              if (htab->root.srelplt != NULL)
                {
                  s = htab->root.srelplt->output_section;
                  dyn.d_un.d_val -= s->size;
                }
              break;
            }

          bfd_elf64_swap_dyn_out(output_bfd, &dyn, dyncon);
        }
    }

  /* Fill in the special first entry in the procedure linkage table. */
  if (htab->root.splt && htab->root.splt->size > 0)
    {
      /* Fill in the first entry in the procedure linkage table. */
      memcpy(htab->root.splt->contents, 
             bfd_link_pic(info)? elf_ve_plt0_entry_pic : 
                                 elf_ve_plt0_entry,
             htab->plt_header_size);

      /* Insert the relocation positions */
      if (bfd_link_executable(info))
        {
          asection *gotplt = htab->root.sgotplt;
          bfd_put_32(output_bfd,
                     (gotplt->output_section->vma + gotplt->output_offset)
                     & 0xffffffff,
                     htab->root.splt->contents);
          bfd_put_32(output_bfd,
                     (gotplt->output_section->vma + gotplt->output_offset)
                     >> 32,
                     htab->root.splt->contents + 0x10);
        }

      elf_section_data(htab->root.splt->output_section)->this_hdr.sh_entsize
        = htab->plt_header_size;

      /* TODO */
    }

  if (htab->root.sgotplt)
    {
      if (bfd_is_abs_section(htab->root.sgotplt->output_section))
        {
          (*_bfd_error_handler)
            (_("discarded output section: `%A'"), htab->root.sgotplt);
          return FALSE;
        }

      /* Fill in the first three entries in the global offset table. */
      if (htab->root.sgotplt->size > 0)
        {
          if (sdyn == NULL)
            bfd_put_64(output_bfd, (bfd_vma)0, htab->root.sgotplt->contents);
          else
            bfd_put_64(output_bfd,
                       sdyn->output_section->vma + sdyn->output_offset,
                       htab->root.sgotplt->contents);

          /* Write GOT[1] and GOT[2], needed for the dynamic linker. */
          bfd_put_64(output_bfd, (bfd_vma)0,
                     htab->root.sgotplt->contents + GOT_ENTRY_SIZE);
          bfd_put_64(output_bfd, (bfd_vma)0,
                     htab->root.sgotplt->contents + GOT_ENTRY_SIZE * 2);
        }

      if (htab->root.sgot)
        {
          if (htab->root.sgot->size > 0)
            {
              bfd_vma addr =
                sdyn ? sdyn->output_section->vma + sdyn->output_offset : 0;
              bfd_put_64(output_bfd, addr, htab->root.sgot->contents);
            }
        }

      elf_section_data(htab->root.sgotplt->output_section)->this_hdr.sh_entsize
        = GOT_ENTRY_SIZE;
    }

  if (htab->root.sgot && htab->root.sgot->size > 0)
    elf_section_data(htab->root.sgot->output_section)->this_hdr.sh_entsize
      = GOT_ENTRY_SIZE;

  /* Fill PLT and GOT entries for local STT_GNU_IFUNC symbols. */
  htab_traverse(htab->loc_hash_table, elf_ve_finish_local_dynamic_symbol,
                info);

  return TRUE;
}

/* Return address for Ith PLT stub in section PLT, for relocation REL
   or (bfd_vma)-1 if it should not be included. */
static bfd_vma
elf_ve_plt_sym_val(bfd_vma i, const asection *plt,
                       const arelent *rel ATTRIBUTE_UNUSED)
{
  return plt->vma + (i + 1) * PLT_ENTRY_SIZE;	/* TODO */
}

#define TARGET_LITTLE_SYM		ve_elf64_vec
#define TARGET_LITTLE_NAME		"elf64-ve"
#define ELF_ARCH			bfd_arch_ve
#define ELF_MACHINE_CODE                EM_VE
#if 0
#define ELF_MAXPAGESIZE			0x4000000	/* 64MB */
#else
#define ELF_MAXPAGESIZE			0x200000	/* 2MB */
#endif
#define ELF_COMMONPAGESIZE		0x200000	/* 2MB */
#define ELFOSABI_VE			ELFOSABI_STANDALONE	/* TODO */
#define ELF_OSABI			ELFOSABI_VE
#undef ELF_OSABI

#define elf_info_to_howto		elf_ve_info_to_howto
#define elf_info_to_howto_rel		0
#define elf_info_to_howto_rela		0

#define bfd_elf64_close_and_cleanup	elf_ve_close_and_cleanup
#define bfd_elf64_bfd_free_cached_info	elf_ve_free_cached_info
/* #define bfd_elf64_bfd_is_target_special_symbol \
					elf_ve_is_target_special_symbol */
#define bfd_elf64_bfd_link_hash_table_create \
					elf_ve_link_hash_table_create
#define bfd_elf64_bfd_link_hash_table_free \
					elf_ve_link_hash_table_free
#define bfd_elf64_bfd_copy_private_bfd_data \
					elf_ve_copy_private_bfd_data
#define bfd_elf64_bfd_merge_private_bfd_data \
					elf_ve_merge_private_bfd_data
#define bfd_elf64_bfd_print_private_bfd_data \
					elf_ve_print_private_bfd_data
#define bfd_elf64_bfd_reloc_type_lookup elf_ve_reloc_type_lookup
#define bfd_elf64_bfd_reloc_name_lookup elf_ve_reloc_name_lookup
// #define bfd_elf64_bfd_set_private_flags	elf_ve_set_private_flags
// #define bfd_elf64_find_inliner_info	elf_ve_find_inliner_info
// #define bfd_elf64_find_nearest_line	elf_ve_find_nearest_line
#define bfd_elf64_mkobject		elf_ve_mkobject
// #define bfd_elf64_new_section_hook	elf_ve_new_section_hook

#define elf_backend_can_refcount	1
#define elf_backend_can_gc_sections	0	/* ? TODO */
#define elf_backend_plt_readonly	1
#define elf_backend_plt_alignment	3
#define elf_backend_want_got_plt	1
#define elf_backend_want_plt_sym	1
#define elf_backend_may_use_rel_p	0
#define elf_backend_may_use_rela_p	1
#define elf_backend_default_use_rela_p	1
#define elf_backend_rela_normal		1
#define elf_backend_got_header_size	(GOT_ENTRY_SIZE * 3)

// #define elf_backend_add_symbol_hook	elf_ve_add_symbol_hook
#define elf_backend_adjust_dynamic_symbol \
					elf_ve_adjust_dynamic_symbol
#define elf_backend_always_size_sections \
					elf_ve_always_size_sections
#define elf_backend_check_relocs	elf_ve_check_relocs
#define elf_backend_copy_indirect_symbol \
					elf_ve_copy_indirect_symbol
#define elf_backend_create_dynamic_sections \
					elf_ve_create_dynamic_sections
#define elf_backend_init_index_section	_bfd_elf_init_1_index_section /* 2? */
#define elf_backend_finish_dynamic_sections \
					elf_ve_finish_dynamic_sections
#define elf_backend_finish_dynamic_symbol \
					elf_ve_finish_dynamic_symbol
// #define elf_backend_gc_sweep_hook	elf_ve_gc_sweep_hook
#define elf_backend_grok_prstatus	elf_ve_grok_prstatus
#define elf_backend_grok_psinfo		elf_ve_grok_psinfo
#define elf_backend_object_p		elf_ve_elf_object_p
/* #define elf_backend_output_arch_local_syms
					elf_ve_output_arch_local_syms */
#define elf_backend_plt_sym_val		elf_ve_plt_sym_val
/* #define elf_backend_post_process_headers \
					elf_ve_post_process_headers */
#define elf_backend_relocate_section	elf_ve_relocate_section
#define elf_backend_reloc_type_class	elf_ve_reloc_type_class
// #define elf_backend_section_flags	elf_ve_section_flags
// #define elf_backend_section_from_shdr	elf_ve_section_from_shdr
#define elf_backend_size_dynamic_sections \
					elf_ve_size_dynamic_sections
// #define elf_backend_size_info		elf_ve_size_info

#undef elf_backend_static_tls_alignment
#define elf_backend_static_tls_alignment	16

#include "elf64-target.h"
