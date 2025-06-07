/** @file
  IDT table setup.

  Copyright (c) 2006 - 2016, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SecMain.h"

#define SEC_IDT_ENTRY_COUNT  34

typedef struct _SEC_IDT_TABLE {
  //
  // Reserved 8 bytes preceding IDT to store EFI_PEI_SERVICES**, since IDT base
  // address should be 8-byte alignment.
  // Note: For IA32, only the 4 bytes immediately preceding IDT is used to store
  // EFI_PEI_SERVICES**
  //
  UINT64                      PeiService;
  IA32_IDT_GATE_DESCRIPTOR    IdtTable[SEC_IDT_ENTRY_COUNT];
} SEC_IDT_TABLE;

//
// These are IDT entries pointing to 10:FFFFFFE4h.
//
UINT64  mIdtEntryTemplate = 0xffff8e000010ffe4ULL;

/**
  IDT table setup for IA32 and X64
**/
VOID
EFIAPI
IdtTableSetup (
  )
{
  IA32_DESCRIPTOR  IdtDescriptor;
  SEC_IDT_TABLE    IdtTableInStack;
  UINT32           Index;

  // |-------------------|---->
  // |IDT Table          |
  // |-------------------|
  // |PeiService Pointer |    PeiStackSize
  // |-------------------|
  // |                   |
  // |      Stack        |
  // |-------------------|---->
  // |                   |
  // |                   |
  // |      Heap         |    PeiTemporayRamSize
  // |                   |
  // |                   |
  // |-------------------|---->  TempRamBase

  IdtTableInStack.PeiService = 0;
  for (Index = 0; Index < SEC_IDT_ENTRY_COUNT; Index++) {
    ZeroMem ((VOID *)&IdtTableInStack.IdtTable[Index], sizeof (IA32_IDT_GATE_DESCRIPTOR));
    CopyMem ((VOID *)&IdtTableInStack.IdtTable[Index], (VOID *)&mIdtEntryTemplate, sizeof (UINT64));
  }

  IdtDescriptor.Base  = (UINTN)&IdtTableInStack.IdtTable;
  IdtDescriptor.Limit = (UINT16)(sizeof (IdtTableInStack.IdtTable) - 1);

  AsmWriteIdtr (&IdtDescriptor);
}
