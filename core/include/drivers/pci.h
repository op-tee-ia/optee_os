/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Intel Corporation
 */

#ifndef DRIVER_PCI_H
#define DRIVER_PCI_H

#include <compiler.h>
#include <types_ext.h>

#define PCI_MAX_DEV_NUM     32
#define PCI_MAX_FUNC_NUM    8

/*
 * struct pci_type0_config - Type 00h Configuration Space Header
 * @vendor_id:              The manufacturer of the device identifier.
 * @device_id:              The particular device identifier.
 * @command:                Control over a device's ability to generate and
 *                          respond to PCI cycles.
 * @status:                 Record status information for PCI bus related
 *                          events.
 * @revision_id:            Device specific revision identifier.
 * @class_code:             Identify the generic function of the device.
 * @cache_line_size:        Specify the system cacheline size.
 * @latency_timer:          The value of the Latency Timer for this PCI bus
 *                          master in units of PCI bus clocks.
 * @header_type:            Identify the layout of the second part of the
 *                          predefined header.
 * @bist:                   Control and status of Built-in Self Test.
 * @base_addr_reg0:         Base Address register 0
 * @base_addr_reg1:         Base Address register 1
 * @base_addr_reg2:         Base Address register 2
 * @base_addr_reg3:         Base Address register 3
 * @base_addr_reg4:         Base Address register 4
 * @base_addr_reg5:         Base Address register 5
 * @cardbus_cis_pointer:    Used by those devices that want to share silicon
 *                          between CardBus and PCI.
 * @subsystem_vendor_id:    Vendor of the add-in card or subsystem.
 * @subsystem_id:           Vendor specific identifier.
 * @expansion_rom_base:     Base address and size information for expansion ROM.
 * @capabilities_pointer:   Point to a linked list of new capabilities
 *                          implemented by this device.
 * @rsvd:                   Reserved.
 * @interrupt_line:         Communicate interrupt line routing information.
 * @interrupt_pin:          Interrupt pin the device (or device function) uses.
 * @min_gnt:                Specify how long a burst period the device needs
 *                          assuming a clock rate of 33 MHz.
 * @max_lat:                Specify how often the device needs to gain access
 *                          to the PCI bus.
 */
struct pci_type0_config {
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t command;
    uint16_t status;
    uint8_t revision_id;
    uint8_t class_code[3];
    uint8_t cache_line_size;
    uint8_t latency_timer;
    uint8_t header_type;
    uint8_t bist;
    uint32_t base_addr_reg0;
    uint32_t base_addr_reg1;
    uint32_t base_addr_reg2;
    uint32_t base_addr_reg3;
    uint32_t base_addr_reg4;
    uint32_t base_addr_reg5;
    uint32_t cardbus_cis_pointer;
    uint16_t subsystem_vendor_id;
    uint16_t subsystem_id;
    uint32_t expansion_rom_base;
    uint8_t capabilities_pointer;
    uint8_t rsvd[7];
    uint8_t interrupt_line;
    uint8_t interrupt_pin;
    uint8_t min_gnt;
    uint8_t max_lat;
};

/* PCI config header fileds */
#define PCI_CONFIG_VENDOR_ID_OFFSET \
    offsetof(struct pci_type0_config, vendor_id)
#define PCI_CONFIG_COMMAND_OFFSET offsetof(struct pci_type0_config, command)
#define PCI_CONFIG_STATUS_OFFSET offsetof(struct pci_type0_config, status)
#define PCI_CONFIG_REVISION_OFFSET offsetof(struct pci_type0_config, revision_id)
#define PCI_CONFIG_BAR0_OFFSET \
    offsetof(struct pci_type0_config, base_addr_reg0)
#define PCI_CONFIG_BAR1_OFFSET \
    offsetof(struct pci_type0_config, base_addr_reg1)
#define PCI_CONFIG_BAR2_OFFSET \
    offsetof(struct pci_type0_config, base_addr_reg2)
#define PCI_CONFIG_CAP_PTR_OFFSET \
    offsetof(struct pci_type0_config, capabilities_pointer)

/*
 * Memory Space bit in Command Register.
 * Control a device's response to Memory Space access.
 */
#define CMD_MEM_SPACE_BIT_POSITION 1

/*
 * Capabilites bit in Status Register.
 * This optional ready-only bit indicates whether or not this device
 * implements the pointer for a New Capabilities linked list at
 * offset 34h.
 */
#define STATUS_CAP_LIST_BIT_POSITION 4

/**
 * union pci_config_address - PCI configuration address
 * @bits:           PCI configuration address in bits
 * @bits.reg:       Register ID of PCI device
 * @bits.function:  Function ID of PCI device
 * @bits.device:    Device ID of PCI device
 * @bits.bus:       Bus ID of PCI device
 * @bits.reserved:  Reserved fields
 * @bits.enable:    Enable bit
 * @uint32:         32-bit value of union
 */

typedef union {
    struct {
        uint32_t reg:8;
        uint32_t function:3;
        uint32_t device:5;
        uint32_t bus:8;
        uint32_t reserved:7;
        uint32_t enable:1;
    } __packed  bits;
    uint32_t uint32;
} __packed  pci_config_address_t;

/* MSI-X capability registers */
#define	PCI_MSIX_FLAGS			2		/* Message Control */
#define PCI_MSIX_FLAGS_ENABLE	0x8000	/* MSI-X enable */

/* MSI-X Table entry format */
#define PCI_MSIX_ENTRY_SIZE		16
#define PCI_MSIX_ENTRY_LOWER_ADDR	0  /* Message Address */
#define PCI_MSIX_ENTRY_UPPER_ADDR	4  /* Message Upper Address */
#define PCI_MSIX_ENTRY_DATA		8  /* Message Data */
#define PCI_MSIX_ENTRY_VECTOR_CTRL	12 /* Vector Control */


/**
 * pci_read8 - Read 8-bit value from PCI device with specified BDF and register
 * @bus:    Bus ID of PCI device
 * @dev:    Device ID of PCI device
 * @func:   Function ID of PCI device
 * @reg:    Register ID of PCI device
 *
 * Return: 8-bit value read from PCI device
 */
uint8_t pci_read8(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg);

/**
 * pci_read16 - Read 16-bit value from PCI device with specified BDF and
 *              register
 * @bus:    Bus ID of PCI device
 * @dev:    Device ID of PCI device
 * @func:   Function ID of PCI device
 * @reg:    Register ID of PCI device
 *
 * Return: 16-bit value read from PCI device
 */
uint16_t pci_read16(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg);

/**
 * pci_read32 - Read 32-bit value from PCI device with specified BDF and
 *              register
 * @bus:    Bus ID of PCI device
 * @dev:    Device ID of PCI device
 * @func:   Function ID of PCI device
 * @reg:    Register ID of PCI device
 *
 * Return: 32-bit value read from PCI device
 */
uint32_t pci_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t reg);

/**
 * pci_write8 - Write 8-bit value to register of PCI device with specified BDF
 * @bus:    Bus ID of PCI device
 * @dev:    Device ID of PCI device
 * @func:   Function ID of PCI device
 * @reg:    Register ID of PCI device
 */
void pci_write8(uint8_t bus,
                uint8_t dev,
                uint8_t func,
                uint8_t reg,
                uint8_t val);

/**
 * pci_write16 - Write 16-bit value to register of PCI device with specified BDF
 * @bus:    Bus ID of PCI device
 * @dev:    Device ID of PCI device
 * @func:   Function ID of PCI device
 * @reg:    Register ID of PCI device
 */
void pci_write16(uint8_t bus,
                 uint8_t dev,
                 uint8_t func,
                 uint8_t reg,
                 uint16_t val);

/**
 * pci_write32 - Write 32-bit value to register of PCI device with specified BDF
 * @bus:    Bus ID of PCI device
 * @dev:    Device ID of PCI device
 * @func:   Function ID of PCI device
 * @reg:    Register ID of PCI device
 */
void pci_write32(uint8_t bus,
                 uint8_t dev,
                 uint8_t func,
                 uint8_t reg,
                 uint32_t val);

/**
 * pci_resource_start - Get PCI BAR address
 */
uint32_t pci_resource_start(uint8_t bus, uint8_t device, uint8_t function,
	uint8_t bar_off);

/**
 * pci_resource_len - Get PCI BAR len
 */
uint32_t pci_resource_len(uint8_t bus, uint8_t device, uint8_t function,
	uint8_t bar_off);

#endif
