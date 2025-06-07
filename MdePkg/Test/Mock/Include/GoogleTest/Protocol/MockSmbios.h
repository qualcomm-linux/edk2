/** @file MockSmbios.h
  This file declares a mock of SMBIOS Protocol.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef MOCK_SMBIOS_PROTOCOL_H_
#define MOCK_SMBIOS_PROTOCOL_H_

#include <Library/GoogleTestLib.h>
#include <Library/FunctionMockLib.h>

extern "C" {
  #include <Uefi.h>
  #include <Protocol/Smbios.h>
}

struct MockEfiSmbiosProtocol {
  MOCK_INTERFACE_DECLARATION (MockEfiSmbiosProtocol);

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    Add,
    (
     IN CONST      EFI_SMBIOS_PROTOCOL     *This,
     IN            EFI_HANDLE              ProducerHandle OPTIONAL,
     IN OUT        EFI_SMBIOS_HANDLE       *SmbiosHandle,
     IN            EFI_SMBIOS_TABLE_HEADER *Record
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UpdateString,
    (
     IN CONST EFI_SMBIOS_PROTOCOL *This,
     IN       EFI_SMBIOS_HANDLE   *SmbiosHandle,
     IN       UINTN               *StringNumber,
     IN       CHAR8               *String
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    Remove,
    (
     IN CONST EFI_SMBIOS_PROTOCOL *This,
     IN       EFI_SMBIOS_HANDLE   SmbiosHandle
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    GetNext,
    (
     IN CONST EFI_SMBIOS_PROTOCOL     *This,
     IN OUT EFI_SMBIOS_HANDLE       *SmbiosHandle,
     IN EFI_SMBIOS_TYPE         *Type OPTIONAL,
     OUT EFI_SMBIOS_TABLE_HEADER **Record,
     OUT EFI_HANDLE              *ProducerHandle OPTIONAL
    )
    );
};

MOCK_INTERFACE_DEFINITION (MockEfiSmbiosProtocol);
MOCK_FUNCTION_DEFINITION (MockEfiSmbiosProtocol, Add, 4, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiSmbiosProtocol, UpdateString, 4, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiSmbiosProtocol, Remove, 2, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiSmbiosProtocol, GetNext, 5, EFIAPI);

#define MOCK_EFI_SMBIOS_PROTOCOL_INSTANCE(NAME) \
  EFI_SMBIOS_PROTOCOL NAME##_INSTANCE = {       \
    Add,                                        \
    UpdateString,                               \
    Remove,                                     \
    GetNext,                                    \
    0,                                          \
    0 };                                        \
  EFI_SMBIOS_PROTOCOL  *NAME = &NAME##_INSTANCE;

#endif // MOCK_SMBIOS_PROTOCOL_H_
