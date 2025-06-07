/** @file MockUsbIo.h
  This file declares a mock of Usb Io Protocol.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef MOCK_USB_IO_H_
#define MOCK_USB_IO_H_

#include <Library/GoogleTestLib.h>
#include <Library/FunctionMockLib.h>

extern "C" {
  #include <Uefi.h>
  #include <Protocol/UsbIo.h>
}

struct MockEfiUsbIoProtocol {
  MOCK_INTERFACE_DECLARATION (MockEfiUsbIoProtocol);

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UsbControlTransfer,
    (
     IN EFI_USB_IO_PROTOCOL                        *This,
     IN EFI_USB_DEVICE_REQUEST                     *Request,
     IN EFI_USB_DATA_DIRECTION                     Direction,
     IN UINT32                                     Timeout,
     IN OUT VOID                                   *Data OPTIONAL,
     IN UINTN                                      DataLength  OPTIONAL,
     OUT UINT32                                    *Status
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UsbBulkTransfer,
    (
     IN EFI_USB_IO_PROTOCOL            *This,
     IN UINT8                          DeviceEndpoint,
     IN OUT VOID                       *Data,
     IN OUT UINTN                      *DataLength,
     IN UINTN                          Timeout,
     OUT UINT32                        *Status
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UsbAsyncInterruptTransfer,
    (
     IN EFI_USB_IO_PROTOCOL                                 *This,
     IN UINT8                                               DeviceEndpoint,
     IN BOOLEAN                                             IsNewTransfer,
     IN UINTN                                               PollingInterval    OPTIONAL,
     IN UINTN                                               DataLength         OPTIONAL,
     IN EFI_ASYNC_USB_TRANSFER_CALLBACK                     InterruptCallBack  OPTIONAL,
     IN VOID                                                *Context OPTIONAL
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UsbSyncInterruptTransfer,
    (
     IN EFI_USB_IO_PROTOCOL            *This,
     IN     UINT8                      DeviceEndpoint,
     IN OUT VOID                       *Data,
     IN OUT UINTN                      *DataLength,
     IN     UINTN                      Timeout,
     OUT    UINT32                     *Status
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UsbIsochronousTransfer,
    (
     IN EFI_USB_IO_PROTOCOL            *This,
     IN     UINT8                      DeviceEndpoint,
     IN OUT VOID                       *Data,
     IN     UINTN                      DataLength,
     OUT    UINT32                     *Status
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UsbAsyncIsochronousTransfer,
    (
     IN EFI_USB_IO_PROTOCOL              *This,
     IN UINT8                            DeviceEndpoint,
     IN OUT VOID                         *Data,
     IN     UINTN                        DataLength,
     IN EFI_ASYNC_USB_TRANSFER_CALLBACK  IsochronousCallBack,
     IN VOID                             *Context OPTIONAL
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UsbGetDeviceDescriptor,
    (
     IN EFI_USB_IO_PROTOCOL            *This,
     OUT EFI_USB_DEVICE_DESCRIPTOR     *DeviceDescriptor
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UsbGetConfigDescriptor,
    (
     IN EFI_USB_IO_PROTOCOL            *This,
     OUT EFI_USB_CONFIG_DESCRIPTOR     *ConfigurationDescriptor
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UsbGetInterfaceDescriptor,
    (
     IN EFI_USB_IO_PROTOCOL            *This,
     OUT EFI_USB_INTERFACE_DESCRIPTOR  *InterfaceDescriptor
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UsbGetEndpointDescriptor,
    (
     IN EFI_USB_IO_PROTOCOL            *This,
     IN  UINT8                         EndpointIndex,
     OUT EFI_USB_ENDPOINT_DESCRIPTOR   *EndpointDescriptor
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UsbGetStringDescriptor,
    (
     IN EFI_USB_IO_PROTOCOL            *This,
     IN  UINT16                        LangID,
     IN  UINT8                         StringID,
     OUT CHAR16                        **StringBuffer
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UsbGetSupportedLanguages,
    (
     IN EFI_USB_IO_PROTOCOL            *This,
     OUT UINT16                        **LangIDTable,
     OUT UINT16                        *TableSize
    )
    );

  MOCK_FUNCTION_DECLARATION (
    EFI_STATUS,
    UsbPortReset,
    (
     IN EFI_USB_IO_PROTOCOL    *This
    )
    );
};

MOCK_INTERFACE_DEFINITION (MockEfiUsbIoProtocol);
MOCK_FUNCTION_DEFINITION (MockEfiUsbIoProtocol, UsbControlTransfer, 7, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiUsbIoProtocol, UsbBulkTransfer, 6, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiUsbIoProtocol, UsbAsyncInterruptTransfer, 7, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiUsbIoProtocol, UsbSyncInterruptTransfer, 6, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiUsbIoProtocol, UsbIsochronousTransfer, 5, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiUsbIoProtocol, UsbAsyncIsochronousTransfer, 6, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiUsbIoProtocol, UsbGetDeviceDescriptor, 2, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiUsbIoProtocol, UsbGetConfigDescriptor, 2, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiUsbIoProtocol, UsbGetInterfaceDescriptor, 2, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiUsbIoProtocol, UsbGetEndpointDescriptor, 3, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiUsbIoProtocol, UsbGetStringDescriptor, 4, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiUsbIoProtocol, UsbGetSupportedLanguages, 3, EFIAPI);
MOCK_FUNCTION_DEFINITION (MockEfiUsbIoProtocol, UsbPortReset, 1, EFIAPI);

#define MOCK_EFI_USB_IO_PROTOCOL_INSTANCE(NAME) \
  EFI_USB_IO_PROTOCOL NAME##_INSTANCE = {       \
    UsbControlTransfer,                         \
    UsbBulkTransfer,                            \
    UsbAsyncInterruptTransfer,                  \
    UsbSyncInterruptTransfer,                   \
    UsbIsochronousTransfer,                     \
    UsbAsyncIsochronousTransfer,                \
    UsbGetDeviceDescriptor,                     \
    UsbGetConfigDescriptor,                     \
    UsbGetInterfaceDescriptor,                  \
    UsbGetEndpointDescriptor,                   \
    UsbGetStringDescriptor,                     \
    UsbGetSupportedLanguages,                   \
    UsbPortReset };                             \
  EFI_USB_IO_PROTOCOL  *NAME = &NAME##_INSTANCE;

#endif // MOCK_USB_IO_H_
