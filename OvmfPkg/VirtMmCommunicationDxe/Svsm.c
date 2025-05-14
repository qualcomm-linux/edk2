/** @file

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/BaseLib.h>

#include <Library/AmdSvsmLib.h>
#include <Register/Amd/Msr.h>
#include <Register/Amd/Svsm.h>

#include "VirtMmCommunication.h"

static BOOLEAN  mRuntime;

BOOLEAN
EFIAPI
VirtMmSvsmProbe (
  VOID
  )
{
  UINT32  Min, Max;

  if (!AmdSvsmIsSvsmPresent ()) {
    DEBUG ((DEBUG_VERBOSE, "%a: no SVSM present\n", __func__));
    return FALSE;
  }

  if (!AmdSvsmQueryProtocol (SVSM_UEFI_MM_PROTOCOL, 1, &Min, &Max)) {
    DEBUG ((DEBUG_VERBOSE, "%a: SVSM UEFI MM protocol not supported\n", __func__));
    return FALSE;
  }

  DEBUG ((
    DEBUG_INFO,
    "%a: SVSM UEFI MM protocol available (min %d, max %d)\n",
    __func__,
    Min,
    Max
    ));
  return TRUE;
}

EFI_STATUS
EFIAPI
VirtMmSvsmInit (
  VOID
  )
{
  UINT64  Rcx, Rdx;

  ASSERT (AmdSvsmIsSvsmPresent ());

  AmdSvsmUefiMmCall (SVSM_UEFI_MM_UNREGISTER_BUFFER, 0, 0, FALSE);

  Rcx = (UINT64)(UINTN)mCommunicateBufferPhys;
  Rdx = MAX_BUFFER_SIZE;
  if (!AmdSvsmUefiMmCall (SVSM_UEFI_MM_REGISTER_BUFFER, Rcx, Rdx, FALSE)) {
    DEBUG ((DEBUG_ERROR, "%a: SVSM_UEFI_MM_SETUP failed\n", __func__));
    return EFI_DEVICE_ERROR;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
VirtMmSvsmVirtMap (
  VOID
  )
{
  DEBUG ((DEBUG_VERBOSE, "%a: going virtual\n", __func__));
  mRuntime = TRUE;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
VirtMmSvsmComm (
  VOID
  )
{
  ASSERT (AmdSvsmIsSvsmPresent ());

  DEBUG ((DEBUG_VERBOSE, "%a: request doorbell\n", __func__));
  if (!AmdSvsmUefiMmCall (SVSM_UEFI_MM_REQUEST_DOORBELL, 0, 0, mRuntime)) {
    DEBUG ((DEBUG_ERROR, "%a: SVSM_UEFI_MM_REQUEST failed\n", __func__));
    return EFI_DEVICE_ERROR;
  }

  return EFI_SUCCESS;
}
