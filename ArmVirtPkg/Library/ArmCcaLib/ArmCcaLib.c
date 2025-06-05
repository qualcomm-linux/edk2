/** @file
  Library that implements the Arm CCA helper functions.

  Copyright (c) 2022 - 2023, Arm Limited. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

  @par Glossary:
    - Rsi or RSI   - Realm Service Interface
    - IPA          - Intermediate Physical Address
    - RIPAS        - Realm IPA state
**/
#include <Base.h>

#include <Library/ArmCcaLib.h>
#include <Library/ArmCcaRsiLib.h>
#include <Library/ArmMmuLib.h>
#include <Library/BaseLib.h>

#include <Uefi/UefiMultiPhase.h>
#include <Uefi/UefiSpec.h>
#include <Pi/PiBootMode.h>
#include <Pi/PiHob.h>
#include <Library/HobLib.h>

/**
  Check if running in a Realm.

    @retval TRUE    The execution is within the context of a Realm.
    @retval FALSE   The execution is not within the context of a Realm.
**/
BOOLEAN
EFIAPI
IsRealm (
  VOID
  )
{
  RETURN_STATUS   Status;
  UINT32          UefiImpl;
  UINT32          RmmImplLow;
  UINT32          RmmImplHigh;
  STATIC BOOLEAN  RealmWorld       = FALSE;
  STATIC BOOLEAN  FlagsInitialised = FALSE;

  if (!FlagsInitialised) {
    FlagsInitialised = TRUE;
    if (ArmHasRme ()) {
      Status = RsiGetVersion (
                 &UefiImpl,
                 &RmmImplLow,
                 &RmmImplHigh
                 );
      if (!RETURN_ERROR (Status)) {
        RealmWorld = TRUE;
      }
    }
  }

  return RealmWorld;
}

/**
  Configure the protection attribute for the page tables
  describing the memory region.

  The IPA space of a Realm is divided into two halves:
    - Protected IPA space and
    - Unprotected IPA space.

  Software in a Realm should treat the most significant bit of an
  IPA as a protection attribute.

  A Protected IPA is an address in the lower half of a Realms IPA
  space. The most significant bit of a Protected IPA is 0.

  An Unprotected IPA is an address in the upper half of a Realms
  IPA space. The most significant bit of an Unprotected IPA is 1.

  Note:
  - Configuring the memory region as Unprotected IPA enables the
    Realm to share the memory region with the Host.
  - This function updates the page table entries to reflect the
    protection attribute.
  - A separate call to transition the memory range using the Realm
    Service Interface (RSI) RSI_IPA_STATE_SET command is additionally
    required and is expected to be done outside this function.

    @param [in]  BaseAddress  Base address of the memory region.
    @param [in]  Length       Length of the memory region.
    @param [in]  IpaWidth     IPA width of the Realm.
    @param [in]  Share        If TRUE, set the most significant
                              bit of the IPA to configure the memory
                              region as Unprotected IPA.
                              If FALSE, clear the most significant
                              bit of the IPA to configure the memory
                              region as Protected IPA.

    @retval RETURN_SUCCESS            IPA protection attribute updated.
    @retval RETURN_INVALID_PARAMETER  A parameter is invalid.
    @retval RETURN_UNSUPPORTED        The request is not initiated in a
                                      Realm.
**/
RETURN_STATUS
EFIAPI
ArmCcaSetMemoryProtectAttribute (
  IN EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN UINT64                Length,
  IN UINT64                IpaWidth,
  IN BOOLEAN               Share
  )
{
  if (!IsRealm ()) {
    return RETURN_UNSUPPORTED;
  }

  if ((Length == 0) || (IpaWidth == 0)) {
    return RETURN_INVALID_PARAMETER;
  }

  return SetMemoryProtectionAttribute (
           BaseAddress,
           Length,
           IpaWidth,
           Share
           );
}

/**
  Return the IPA width of the Realm.

  The IPA width of the Realm is used to configure the protection attribute
  for memory regions, see ArmCcaSetMemoryProtectAttribute().

  The IPA width of the Realm is present in the Realm config which is read
  when the ArmCcaInitPeiLib library hook function ArmCcaInitialize () is
  called in the PrePi phase. ArmCcaInitialize () stores the IPA width of
  the Realm in a GUID HOB gArmCcaIpaWidthGuid.

  This function searches the GUID HOB gArmCcaIpaWidthGuid and returns the
  IPA width value stored therein.

  Note:
  - This function must only be called after ArmCcaInitialize () has setup
    the GUID HOB gArmCcaIpaWidthGuid.

    @param [out] IpaWidth  IPA width of the Realm.

    @retval RETURN_SUCCESS            Success.
    @retval RETURN_INVALID_PARAMETER  A parameter is invalid.
    @retval RETURN_NOT_FOUND          The GUID HOB gArmCcaIpaWidthGuid is not
                                      found and could mean that this function
                                      was called before ArmCcaInitialize ()
                                      has created and initialised the GUID
                                      HOB gArmCcaIpaWidthGuid.
**/
RETURN_STATUS
EFIAPI
GetIpaWidth (
  OUT UINT64  *IpaWidth
  )
{
  VOID    *Hob;
  UINT64  *CcaIpaWidth;

  if (IpaWidth == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  Hob = GetFirstGuidHob (&gArmCcaIpaWidthGuid);
  if ((Hob == NULL) ||
      (GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (UINT64)))
  {
    return RETURN_NOT_FOUND;
  }

  CcaIpaWidth = GET_GUID_HOB_DATA (Hob);
  if ((UINT64)*CcaIpaWidth == 0) {
    return RETURN_NOT_FOUND;
  }

  *IpaWidth = *CcaIpaWidth;

  return RETURN_SUCCESS;
}

/** Check if the address range is protected MMIO

  @param [in]   BaseAddress      Base address of the device MMIO region.
  @param [in]   Length           Length of the device MMIO region.
  @param [out]  IsProtectedMmio  TRUE - if the RIPAS for the address range is
                                        protected MMIO.
                                 FALSE - if the RIPAS for the address range is
                                         not protected MMIO.

  @retval RETURN_SUCCESS            Success.
  @retval RETURN_INVALID_PARAMETER  A parameter is invalid.
  @retval RETURN_UNSUPPORTED        The request is not initiated in a
                                    Realm.
**/
RETURN_STATUS
EFIAPI
ArmCcaMemRangeIsProtectedMmio (
  IN  UINT64   BaseAddress,
  IN  UINT64   Length,
  OUT BOOLEAN  *IsProtectedMmio
  )
{
  RETURN_STATUS  RetStatus;
  UINT64         *Base;
  UINT64         *Top;
  UINT64         *End;
  RIPAS          State;

  if ((Length == 0) || (IsProtectedMmio == NULL)) {
    return RETURN_INVALID_PARAMETER;
  }

  Base = (UINT64 *)BaseAddress;
  End  = (UINT64 *)(BaseAddress + Length);

  while (Base < End) {
    Top       = End;
    RetStatus = RsiGetIpaState (
                  Base,
                  &Top,
                  &State
                  );
    if (RETURN_ERROR (RetStatus)) {
      // An error occurred.
      return RetStatus;
    }

    if ((Top <= Base) || (State != RipasDev)) {
      // The address range is not protected MMIO.
      *IsProtectedMmio = FALSE;
      return RetStatus;
    }

    Base = Top;
  } // while

  *IsProtectedMmio = TRUE;
  return RETURN_SUCCESS;
}
