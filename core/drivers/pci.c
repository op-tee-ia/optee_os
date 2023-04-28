// SPDX-License-Identifier: BSD-2-Clause
/*
 *  Copyright (c) 2022 Intel Corporation
 */

#include <drivers/pci.h>


#define PCI_CONFIG_ADDRESS_REGISTER 0xCF8
#define PCI_CONFIG_DATA_REGISTER    0xCFC


static uint8_t hw_read_port_8(uint16_t port)
{
    uint8_t val8;

    __asm__ __volatile__ (
        "in %1, %0"
        : "=a" (val8)
        : "d" (port)
    );

    return val8;
}

static uint16_t hw_read_port_16(uint16_t port)
{
    uint16_t val16;

    __asm__ __volatile__ (
        "in %1, %0"
        : "=a" (val16)
        : "d" (port)
    );

    return val16;
}

static uint32_t hw_read_port_32(uint16_t port)
{
    uint32_t val32;

    __asm__ __volatile__ (
        "in %1, %0"
        : "=a" (val32)
        : "d" (port)
    );

    return val32;
}

static void hw_write_port_8(uint16_t port, uint8_t val8)
{
    __asm__ __volatile__ (
        "out %1, %0"
        :
        : "d" (port), "a" (val8)
    );
}

static void hw_write_port_16(uint16_t port, uint16_t val16)
{
    __asm__ __volatile__ (
        "out %1, %0"
        :
        : "d" (port), "a" (val16)
    );
}

static void hw_write_port_32(uint16_t port, uint32_t val32)
{
    __asm__ __volatile__ (
        "out %1, %0"
        :
        : "d" (port), "a" (val32)
    );
}

uint8_t pci_read8(uint8_t bus, uint8_t device, uint8_t function, uint8_t reg)
{
    pci_config_address_t addr;

    addr.uint32 = 0;
    addr.bits.bus = bus;
    addr.bits.device = device;
    addr.bits.function = function;
    addr.bits.reg = reg;
    addr.bits.enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.uint32 & ~0x3);
    return hw_read_port_8(PCI_CONFIG_DATA_REGISTER | (addr.uint32 & 0x3));
}

void pci_write8(uint8_t bus, uint8_t device, uint8_t function, uint8_t reg, uint8_t value)
{
    pci_config_address_t addr;

    addr.uint32 = 0;
    addr.bits.bus = bus;
    addr.bits.device = device;
    addr.bits.function = function;
    addr.bits.reg = reg;
    addr.bits.enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.uint32 & ~0x3);
    hw_write_port_8(PCI_CONFIG_DATA_REGISTER | (addr.uint32 & 0x3), value);
}

uint16_t pci_read16(uint8_t bus, uint8_t device, uint8_t function, uint8_t reg)
{
    pci_config_address_t addr;

    addr.uint32 = 0;
    addr.bits.bus = bus;
    addr.bits.device = device;
    addr.bits.function = function;
    addr.bits.reg = reg;
    addr.bits.enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.uint32 & ~0x3);
    return hw_read_port_16(PCI_CONFIG_DATA_REGISTER | (addr.uint32 & 0x3));
}

void pci_write16(uint8_t bus, uint8_t device, uint8_t function, uint8_t reg, uint16_t value)
{
    pci_config_address_t addr;

    addr.uint32 = 0;
    addr.bits.bus = bus;
    addr.bits.device = device;
    addr.bits.function = function;
    addr.bits.reg = reg;
    addr.bits.enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.uint32 & ~0x3);
    //TODO: check if it's right
    hw_write_port_16(PCI_CONFIG_DATA_REGISTER | (addr.uint32 & 0x2), value);
}

uint32_t pci_read32(uint8_t bus, uint8_t device, uint8_t function, uint8_t reg)
{
    pci_config_address_t addr;

    addr.uint32 = 0;
    addr.bits.bus = bus;
    addr.bits.device = device;
    addr.bits.function = function;
    addr.bits.reg = reg;
    addr.bits.enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.uint32 & ~0x3);
    return hw_read_port_32(PCI_CONFIG_DATA_REGISTER);
}

void pci_write32(uint8_t bus, uint8_t device, uint8_t function, uint8_t reg, uint32_t value)
{
    pci_config_address_t addr;

    addr.uint32 = 0;
    addr.bits.bus = bus;
    addr.bits.device = device;
    addr.bits.function = function;
    addr.bits.reg = reg;
    addr.bits.enable = 1;

    hw_write_port_32(PCI_CONFIG_ADDRESS_REGISTER, addr.uint32 & ~0x3);
    hw_write_port_32(PCI_CONFIG_DATA_REGISTER, value);
}

uint32_t pci_resource_start(uint8_t bus, uint8_t device, uint8_t function,
	uint8_t bar_off)
{
	return (pci_read32(bus, device, function, bar_off) & 0xFFFFFFF0);
}

uint32_t pci_resource_len(uint8_t bus, uint8_t device, uint8_t function,
	uint8_t bar_off)
{
	uint32_t bar = 0, len = 0;

	bar = pci_read32(bus, device, function, bar_off);
	pci_write32(bus, device, function, bar_off, 0xFFFFFFFF);
	len = pci_read32(bus, device, function, bar_off);
	pci_write32(bus, device, function, bar_off, bar);
	if (len == 0x0) {
		return 0x0;
	} else {
		return (~(len & 0xFFFFFFF0) + 1);
	}
}

