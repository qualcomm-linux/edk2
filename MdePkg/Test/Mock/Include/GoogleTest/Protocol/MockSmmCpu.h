/** @file MockSmmCpu.h
  This file declares a mock of Smm CPU Protocol.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef MOCK_SMM_CPU_H_
#define MOCK_SMM_CPU_H_

#include <Library/GoogleTestLib.h>
#include <Library/FunctionMockLib.h>

extern "C" {
  #include <Uefi.h>
  #include <Protocol/SmmCpu.h>
}

struct MockEfiSmmCpuProtocol {
  MOCK_INTERFACE_DECLARATION (MockEfiSmmCpuProtocol);

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    ReadSaveState,
    (
     IN CONST EFI_MM_CPU_PROTOCOL    *This,
     IN UINTN                        Width,
     IN EFI_MM_SAVE_STATE_REGISTER   Register,
     IN UINTN                        CpuIndex,
     OUT VOID                        *Buffer
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    WriteSaveState,
    (
     IN CONST EFI_MM_CPU_PROTOCOL    *This,
     IN UINTN                        Width,
     IN EFI_MM_SAVE_STATE_REGISTER   Register,
     IN UINTN                        CpuIndex,
     IN CONST VOID                   *Buffer
    )
    );
};

MOCK_INTERFACE_DEFINITION (MockEfiSmmCpuProtocol);
MOCK_FUNCTION_DEFINITION (MockEfiSmmCpuProtocol, ReadSaveState, 5, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiSmmCpuProtocol, WriteSaveState, 5, EFIAPI);

#define MOCK_EFI_SMM_CPU_PROTOCOL_INSTANCE(NAME)  \
  EFI_SMM_CPU_PROTOCOL NAME##_INSTANCE = {        \
    ReadSaveState,                                \
    WriteSaveState };                             \
  EFI_SMM_CPU_PROTOCOL  *NAME = &NAME##_INSTANCE;

#endif // MOCK_SMM_CPU_H_
