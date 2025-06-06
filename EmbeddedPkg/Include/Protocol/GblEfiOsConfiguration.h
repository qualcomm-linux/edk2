/** @file

  Copyright (c) 2025, The Android Open Source Project.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

/*
  GBL EFI OS Configuration Protocol.
  Lets firmware fix up kernel command-line, bootconfig, and choose device-tree
  components at boot time.
*/

#ifndef GBL_EFI_OS_CONFIGURATION_PROTOCOL_H_
#define GBL_EFI_OS_CONFIGURATION_PROTOCOL_H_

#include <Uefi/UefiBaseType.h>

//
// {dda0d135-aa5b-42ff-85ac-e3ad6efb4619}
//
#define GBL_EFI_OS_CONFIGURATION_PROTOCOL_GUID \
  { 0xdda0d135, 0xaa5b, 0x42ff, { 0x85, 0xac, 0xe3, 0xad, 0x6e, 0xfb, 0x46, 0x19 } }

// Still in progress
#define GBL_EFI_OS_CONFIGURATION_PROTOCOL_REVISION  0x00000000

typedef struct _GBL_EFI_OS_CONFIGURATION_PROTOCOL  GBL_EFI_OS_CONFIGURATION_PROTOCOL;
typedef struct _GBL_EFI_DEVICE_TREE_METADATA       GBL_EFI_DEVICE_TREE_METADATA;
typedef struct _GBL_EFI_VERIFIED_DEVICE_TREE       GBL_EFI_VERIFIED_DEVICE_TREE;

/*
  Device-tree component type.
*/
typedef enum {
  GBL_EFI_OS_CONFIGURATION_DEVICE_TREE,
  GBL_EFI_OS_CONFIGURATION_OVERLAY,
  GBL_EFI_OS_CONFIGURATION_PVM_DA_OVERLAY,
} GBL_EFI_DEVICE_TREE_TYPE;

/*
  Source partition the device-tree component came from.
*/
typedef enum {
  GBL_EFI_OS_CONFIGURATION_BOOT,
  GBL_EFI_OS_CONFIGURATION_VENDOR_BOOT,
  GBL_EFI_OS_CONFIGURATION_DTBO,
  GBL_EFI_OS_CONFIGURATION_DTB,
} GBL_EFI_DEVICE_TREE_SOURCE;

/*
  Per-component metadata passed to firmware.
*/
struct _GBL_EFI_DEVICE_TREE_METADATA {
  UINT32    Source; // GBL_EFI_DEVICE_TREE_SOURCE
  UINT32    Type;   // GBL_EFI_DEVICE_TREE_TYPE
  UINT32    Id;
  UINT32    Rev;
  UINT32    Custom[4];
};

/*
  Verified device-tree component plus FW-chosen “Selected” flag.
*/
struct _GBL_EFI_VERIFIED_DEVICE_TREE {
  GBL_EFI_DEVICE_TREE_METADATA    Metadata;
  CONST VOID                      *DeviceTree; // 8-byte aligned, never NULL
  BOOLEAN                         Selected;
};

/// Supply kernel-command-line fixups.
typedef
EFI_STATUS
(EFIAPI *GBL_EFI_FIXUP_KERNEL_COMMANDLINE)(
  IN  GBL_EFI_OS_CONFIGURATION_PROTOCOL  *This,
  IN  CONST CHAR8                        *CommandLine,
  OUT CHAR8                              *Fixup,
  IN  OUT UINTN                          *FixupBufferSize
  );

/// Supply bootconfig fixups.
typedef
EFI_STATUS
(EFIAPI *GBL_EFI_FIXUP_BOOTCONFIG)(
  IN  GBL_EFI_OS_CONFIGURATION_PROTOCOL  *This,
  IN  CONST CHAR8                        *BootConfig,
  IN  UINTN                              BootConfigSize,
  OUT CHAR8                              *Fixup,
  IN  OUT UINTN                          *FixupBufferSize
  );

/// Choose which DT components to include.
typedef
EFI_STATUS
(EFIAPI *GBL_EFI_SELECT_DEVICE_TREES)(
  IN  GBL_EFI_OS_CONFIGURATION_PROTOCOL  *This,
  IN  OUT GBL_EFI_VERIFIED_DEVICE_TREE   *DeviceTrees,
  IN  UINTN                              NumDeviceTrees
  );

/*
  Firmware-published protocol instance.
*/
struct _GBL_EFI_OS_CONFIGURATION_PROTOCOL {
  UINT64                              Revision;
  GBL_EFI_FIXUP_KERNEL_COMMANDLINE    FixupKernelCommandline;
  GBL_EFI_FIXUP_BOOTCONFIG            FixupBootConfig;
  GBL_EFI_SELECT_DEVICE_TREES         SelectDeviceTrees;
};

#endif // GBL_EFI_OS_CONFIGURATION_PROTOCOL_H_
