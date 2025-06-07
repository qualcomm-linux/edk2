/** @file
  Arm FF-A ns common library Header file

  Copyright (c) 2024, Arm Limited. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

  @par Glossary:
     - FF-A - Firmware Framework for Arm A-profile
     - spmc - Secure Partition Manager Core
     - spmd - Secure Partition Manager Dispatcher

  @par Reference(s):
     - Arm Firmware Framework for Arm A-Profile [https://developer.arm.com/documentation/den0077/latest]

**/

#ifndef ARM_FFA_COMMON_LIB_H_
#define ARM_FFA_COMMON_LIB_H_

/**
 * Arguments to call FF-A request via SMC/SVC.
 */
typedef struct ArmFfaArgs {
  UINTN    Arg0;
  UINTN    Arg1;
  UINTN    Arg2;
  UINTN    Arg3;
  UINTN    Arg4;
  UINTN    Arg5;
  UINTN    Arg6;
  UINTN    Arg7;
  UINTN    Arg8;
  UINTN    Arg9;
  UINTN    Arg10;
  UINTN    Arg11;
  UINTN    Arg12;
  UINTN    Arg13;
  UINTN    Arg14;
  UINTN    Arg15;
  UINTN    Arg16;
  UINTN    Arg17;
} ARM_FFA_ARGS;

extern BOOLEAN  gFfaSupported;
extern UINT16   gPartId;

/**
  Convert FfArgs to EFI_STATUS.

  @param [in] FfaArgs            Ffa arguments

  @retval EFI_STATUS             return value correspond EFI_STATUS to FfaStatus

**/
EFI_STATUS
EFIAPI
FfaArgsToEfiStatus (
  IN ARM_FFA_ARGS  *FfaArgs
  );

/**
  Trigger FF-A ABI call according to PcdFfaLibConduitSmc.

  @param [in out]  FfaArgs        Ffa arguments

**/
VOID
EFIAPI
ArmCallFfa (
  IN OUT ARM_FFA_ARGS  *FfaArgs
  );

/**
  Common ArmFfaLib Constructor.

  @retval EFI_SUCCESS
  @retval Others                  Error

**/
EFI_STATUS
EFIAPI
ArmFfaLibCommonInit (
  IN VOID
  );

/**
  Get first Rx/Tx Buffer allocation hob.
  If UseGuid is TRUE, BufferAddr and BufferSize parameters are ignored.

  @param[in]  BufferAddr       Buffer address
  @param[in]  BufferSize       Buffer Size
  @param[in]  UseGuid          Get MemoryAllocationHob using Guid

  @retval     NULL             Not found
  @retval     Other            MemoryAllocationHob related to Rx/Tx buffer

**/
EFI_HOB_MEMORY_ALLOCATION *
EFIAPI
GetRxTxBufferAllocationHob (
  IN EFI_PHYSICAL_ADDRESS  BufferAddr,
  IN UINT64                BufferSize,
  IN BOOLEAN               UseGuid
  );

#endif
