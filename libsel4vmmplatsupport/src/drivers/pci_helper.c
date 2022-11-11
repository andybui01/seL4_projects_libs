/*
 * Copyright 2019, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sel4/sel4.h>

#include <pci/virtual_pci.h>
#include <pci/helper.h>

#include <sel4vmmplatsupport/drivers/pci_helper.h>

#define PCI_CAPABILITY_SPACE_OFFSET 0x40

typedef struct x86_msi_data {
    union {
        struct {
            uint32_t vector		        :8,
                     delivery_mode		:3,
                     dest_mode_logical	:1,
                     reserved		    :2,
                     active_low		    :1,
                     is_level		    :1;
        };
        uint32_t value;
    };
} __attribute__((packed)) x86_msi_data_t;

typedef struct x86_msi_addr_lo {
    union {
        struct {
            uint32_t reserved_0		    :2,
                     dest_mode_logical	:1,
                     redirect_hint		:1,
                     reserved_1		    :1,
                     virt_destid_8_14	:7,
                     destid_0_7		    :8,
                     base_address		:12; /* Always 0xFEE */
        };
        uint32_t value;
    };
} __attribute__((packed)) x86_msi_addr_lo_t;

void *pt_cookie;
uint32_t msi_off;
uint32_t msix_off;

/* Read PCI memory device */
int vmm_pci_mem_device_read(void *cookie, int offset, int size, uint32_t *result)
{
    if (offset < 0) {
        ZF_LOGE("Offset should not be negative");
        return -1;
    }
    if (offset + size > PCI_CAPABILITY_SPACE_OFFSET) {
        ZF_LOGE("Indexing capability space not yet supported, returning 0");
        *result = 0;
        return 0;
    }
    *result = 0;
    /* Read the PCI device field at the given offset
     * We are passed the device header through the cookie parameter */
    memcpy(result, cookie + offset, size);
    return 0;
}

/* Write PCI memory device */
int vmm_pci_mem_device_write(void *cookie, int offset, int size, uint32_t value)
{
    if (offset < 0) {
        ZF_LOGE("Offset should not be negative");
        return -1;
    }
    if (offset + size > PCI_CAPABILITY_SPACE_OFFSET) {
        ZF_LOGE("Indexing capability space not yet supported, returning 0");
        return 0;
    }

    /* Ensure we aren't writing data greater than the size of 'value' */
    if (size > sizeof(value)) {
        ZF_LOGE("Unable to perform a read of size 0x%x", size);
        return -1;
    }

    /* Write the PCI device field at the given offset
     * We are passed the device header through the cookie parameter */
    memcpy(cookie + offset, &value, size);

    return 0;
}

int vmm_pci_entry_ignore_write(void *cookie, int offset, int size, uint32_t value)
{
    ZF_LOGI("Ignoring PCI entry write @ offset 0x%x", offset);
    return 0;
}

void define_pci_host_bridge(vmm_pci_device_def_t *bridge)
{
    *bridge = (vmm_pci_device_def_t) {
        .vendor_id = 0x5E14,
        .device_id = 0x42,
        .command = 0,
        .status = 0,
        .revision_id = 0x1,
        .prog_if = 0,
        .subclass = 0x0,
        .class_code = 0x06,
        .cache_line_size = 0,
        .latency_timer = 0,
        .header_type = 0x00,
        .bist = 0,
        .bar0 = 0,
        .bar1 = 0,
        .bar2 = 0,
        .bar3 = 0,
        .bar4 = 0,
        .bar5 = 0,
        .cardbus = 0,
        .subsystem_vendor_id = 0,
        .subsystem_id = 0,
        .expansion_rom = 0,
        .caps_pointer = 0,
        .reserved1 = 0,
        .reserved2 = 0,
        .reserved3 = 0,
        .interrupt_line = 0,
        .interrupt_pin = 0,
        .min_grant = 0,
        .max_latency = 0,
        .caps_len = 0,
        .caps = NULL
    };
}

static int passthrough_pci_config_ioread(void *cookie, int offset, int size, uint32_t *result)
{
    pci_passthrough_device_t *dev = (pci_passthrough_device_t *)cookie;
    switch (size) {
    case 1:
        *result = dev->config.ioread8(dev->config.cookie, dev->addr, offset);
        break;
    case 2:
        *result = dev->config.ioread16(dev->config.cookie, dev->addr, offset);
        break;
    case 4:
        *result = dev->config.ioread32(dev->config.cookie, dev->addr, offset);
        break;
    default:
        assert(!"Invalid size");
    }
    return 0;
}

static int passthrough_pci_config_iowrite(void *cookie, int offset, int size, uint32_t val)
{
    pci_passthrough_device_t *dev = (pci_passthrough_device_t *)cookie;
    switch (size) {
    case 1:
        dev->config.iowrite8(dev->config.cookie, dev->addr, offset, val);
        break;
    case 2:
        dev->config.iowrite16(dev->config.cookie, dev->addr, offset, val);
        break;
    case 4:
        dev->config.iowrite32(dev->config.cookie, dev->addr, offset, val);
        break;
    default:
        assert(!"Invalid size");
    }
    return 0;
}

static int pci_bar_emul_check_range(unsigned int offset, unsigned int size)
{
    if (offset < PCI_BASE_ADDRESS_0 || offset + size > PCI_BASE_ADDRESS_5 + 4) {
        return 1;
    }
    return 0;
}

static uint32_t pci_make_bar(pci_bar_emulation_t *emul, int bar)
{
    if (bar >= emul->num_bars) {
        return 0;
    }
    uint32_t raw = 0;
    raw |= emul->bars[bar].address;
    if (!(emul->bars[bar].mem_type)) {
        raw |= 1;
    } else {
        if (emul->bars[bar].mem_type == PREFETCH_MEM) {
            raw |= BIT(3);
        }
    }
    raw |= (emul->bar_writes[bar] & ~MASK(emul->bars[bar].size_bits));
    return raw;
}

static int pci_irq_emul_read(void *cookie, int offset, int size, uint32_t *result)
{
    pci_irq_emulation_t *emul = (pci_irq_emulation_t *)cookie;
    if (offset <= PCI_INTERRUPT_LINE && offset + size > PCI_INTERRUPT_LINE) {
        /* do the regular read, then patch in our value */
        int ret = emul->passthrough.ioread(emul->passthrough.cookie, offset, size, result);
        if (ret) {
            return ret;
        }
        int bit_offset = (PCI_INTERRUPT_LINE - offset) * 8;
        *result &= ~(MASK(8) << bit_offset);
        *result |= (emul->irq << bit_offset);
        return 0;
    } else {
        return emul->passthrough.ioread(emul->passthrough.cookie, offset, size, result);
    }
}
/** @andyb: this calls the actual iowrite function which writes to the cap */
static int pci_irq_emul_write(void *cookie, int offset, int size, uint32_t value)
{
    pci_irq_emulation_t *emul = (pci_irq_emulation_t *)cookie;
    if (offset == PCI_INTERRUPT_LINE && size == 1) {
        /* ignore */
        return 0;
    } else if (offset < PCI_INTERRUPT_LINE && offset + size >= PCI_INTERRUPT_LINE) {
        assert(!"Guest writing PCI configuration in an unsupported way");
        return -1;
    } else {
        return emul->passthrough.iowrite(emul->passthrough.cookie, offset, size, value);
    }
}

static int pci_bar_emul_read(void *cookie, int offset, int size, uint32_t *result)
{
    pci_bar_emulation_t *emul = (pci_bar_emulation_t *)cookie;
    if (pci_bar_emul_check_range(offset, size)) {
        return emul->passthrough.ioread(emul->passthrough.cookie, offset, size, result);
    }
    /* Construct the bar value */
    int bar = (offset - PCI_BASE_ADDRESS_0) / 4;
    int bar_offset = offset & 3;
    uint32_t bar_raw = pci_make_bar(emul, bar);
    char *barp = (char *)&bar_raw;
    *result = 0;
    memcpy(result, barp + bar_offset, size);
    return 0;
}

static int pci_bar_emul_write(void *cookie, int offset, int size, uint32_t value)
{
    pci_bar_emulation_t *emul = (pci_bar_emulation_t *)cookie;
    if (pci_bar_emul_check_range(offset, size)) {
        return emul->passthrough.iowrite(emul->passthrough.cookie, offset, size, value);
    }
    /* Construct the bar value */
    int bar = (offset - PCI_BASE_ADDRESS_0) / 4;
    int bar_offset = offset & 3;
    char *barp = (char *)&emul->bar_writes[bar];
    memcpy(barp + bar_offset, &value, size);
    return 0;
}

vmm_pci_entry_t vmm_pci_create_bar_emulation(vmm_pci_entry_t existing, int num_bars, vmm_pci_bar_t *bars)
{
    pci_bar_emulation_t *bar_emul = calloc(1, sizeof(*bar_emul));
    assert(bar_emul);
    memcpy(bar_emul->bars, bars, sizeof(vmm_pci_bar_t) * num_bars);
    bar_emul->passthrough = existing;
    bar_emul->num_bars = num_bars;
    memset(bar_emul->bar_writes, 0, sizeof(bar_emul->bar_writes));
    return (vmm_pci_entry_t) {
        .cookie = bar_emul, .ioread = pci_bar_emul_read, .iowrite = pci_bar_emul_write
    };
}

vmm_pci_entry_t vmm_pci_create_irq_emulation(vmm_pci_entry_t existing, int irq)
{
    pci_irq_emulation_t *irq_emul = calloc(1, sizeof(*irq_emul));
    assert(irq_emul);
    irq_emul->passthrough = existing;
    irq_emul->irq = irq;
    return (vmm_pci_entry_t) {
        .cookie = irq_emul, .ioread = pci_irq_emul_read, .iowrite = pci_irq_emul_write
    };
}

vmm_pci_entry_t vmm_pci_create_passthrough(vmm_pci_address_t addr, vmm_pci_config_t config)
{
    pci_passthrough_device_t *dev = calloc(1, sizeof(*dev));
    assert(dev);
    dev->addr = addr;
    dev->config = config;
    ZF_LOGI("Creating passthrough device for %02x:%02x.%d", addr.bus, addr.dev, addr.fun);
    return (vmm_pci_entry_t) {
        .cookie = dev, .ioread = passthrough_pci_config_ioread, .iowrite = passthrough_pci_config_iowrite
    };
}

static int pci_cap_emul_read(void *cookie, int offset, int size, uint32_t *result)
{
    pci_cap_emulation_t *emul = (pci_cap_emulation_t *)cookie;
    if (offset <= PCI_STATUS && offset + size > PCI_STATUS) {
        /* do the regular read, then patch in our value */
        int ret = emul->passthrough.ioread(emul->passthrough.cookie, offset, size, result);
        if (ret) {
            return ret;
        }
        int bit_offset = (PCI_STATUS - offset) * 8;
        *result &= ~(PCI_STATUS_CAP_LIST << bit_offset);
        if (emul->num_caps > 0) {
            *result |= (PCI_STATUS_CAP_LIST << bit_offset);
        }
        return 0;
    } else if (offset <= PCI_CAPABILITY_LIST && offset + size > PCI_CAPABILITY_LIST) {
        /* do the regular read, then patch in our value */
        int ret = emul->passthrough.ioread(emul->passthrough.cookie, offset, size, result);
        if (ret) {
            return ret;
        }
        int bit_offset = (PCI_CAPABILITY_LIST - offset) * 8;
        *result &= ~(MASK(8) << bit_offset);
        if (emul->num_caps > 0) {
            *result |= (emul->caps[0] << bit_offset);
        }
        return 0;
    }
    /* see if we are reading from any location that we would prefer not to */
    int i;
    for (i = 0; i < emul->num_ignore; i++) {
        if (offset <= emul->ignore_start[i] && offset + size > emul->ignore_end[i]) {
            /* who cares about the size, just ignore everything */
            ZF_LOGI("Attempted read at 0x%x of size %d from region 0x%x-0x%x", offset, size, emul->ignore_start[i],
                    emul->ignore_end[i]);
            *result = 0;
            return 0;
        }
    }
    /* See if we are reading a capability index */
    for (i = 0; i < emul->num_caps; i++) {
        if (offset <= emul->caps[i] + 1 && offset + size > emul->caps[i] + 1) {
            /* do the regular read, then patch in our value */
            int ret = emul->passthrough.ioread(emul->passthrough.cookie, offset, size, result);
            if (ret) {
                return ret;
            }
            int bit_offset = (emul->caps[i] + 1 - offset) * 8;
            *result &= ~(MASK(8) << bit_offset);
            if (i + 1 < emul->num_caps) {
                *result |= (emul->caps[i + 1] << bit_offset);
            }
            return 0;
        }
    }
    /* Pass through whatever is left */
    return emul->passthrough.ioread(emul->passthrough.cookie, offset, size, result);
}

static int msi_cap_emul_write(void *cookie, int offset, int size, uint32_t value)
{
    pci_cap_emulation_t *emul = (pci_cap_emulation_t *)cookie;

    uint32_t temp;
    emul->passthrough.ioread(emul->passthrough.cookie, msi_off, 4, &temp);

    printf("MSI(%d) at off %x: Writing value 0x%x sized %d bytes to cap offset 0x%x\n", (temp&BIT(16))>>16, offset, value, size, offset - msi_off);
    if (offset - msi_off == 0xC) {
        printf("\tVector %d, Delivery Mode 0x%x, Trigger Mode %d\n", value & 0xff, (value >> 8) & 0b111, (value >> 15) & 1);
        x86_msi_data_t *data = &value;
        if (data->vector == 32) {
            data->vector = 16 + 48;
            printf("\tVector %d, Delivery Mode 0x%x, Trigger Mode %d\n", value & 0xff, (value >> 8) & 0b111, (value >> 15) & 1);
        }
    } else if (offset - msi_off == 0x4) {
        x86_msi_addr_lo_t *addr = &value;
        printf("\tDest 0x%x, RH 0x%x, DM 0x%x\n", addr->destid_0_7, addr->redirect_hint, addr->dest_mode_logical);
        addr->value = 0xfee00000;
    }
    
    /** @andyb: call irq emulation */
    return emul->passthrough.iowrite(emul->passthrough.cookie, offset, size, value);
}

static int pci_cap_emul_write(void *cookie, int offset, int size, uint32_t value)
{
    assert(offset != msi_off);
    pci_cap_emulation_t *emul = (pci_cap_emulation_t *)cookie;
    /* Prevents writes to our ignored ranges. but let anything else through */
    int i;
    for (i = 0; i < emul->num_ignore; i++) {
        if (offset <= emul->ignore_start[i] && offset + size > emul->ignore_end[i]) {
            /* who cares about the size, just ignore everything */
            ZF_LOGI("Attempted write at 0x%x of size %d from region 0x%x-0x%x", offset, size, emul->ignore_start[i],
                    emul->ignore_end[i]);
            return 0;
        }
    }

    if (emul->passthrough.cookie == pt_cookie && offset >= msi_off && offset < msi_off + 0x18) {
        msi_cap_emul_write(cookie, offset, size, value);
    } else {
        return emul->passthrough.iowrite(emul->passthrough.cookie, offset, size, value);
    }
}

vmm_pci_entry_t vmm_pci_create_cap_emulation(vmm_pci_entry_t existing, int num_caps, uint8_t *caps, int num_ranges,
                                             uint8_t *range_starts, uint8_t *range_ends)
{
    pci_cap_emulation_t *emul = calloc(1, sizeof(*emul));
    emul->passthrough = existing;
    assert(emul);
    emul->num_caps = num_caps;
    emul->caps = calloc(1, sizeof(uint8_t) * num_caps);
    assert(emul->caps);
    memcpy(emul->caps, caps, sizeof(uint8_t) * num_caps);
    emul->num_ignore = num_ranges;
    emul->ignore_start = calloc(1, sizeof(uint8_t) * num_ranges);
    assert(emul->ignore_start);
    emul->ignore_end = calloc(1, sizeof(uint8_t) * num_ranges);
    assert(emul->ignore_end);
    memcpy(emul->ignore_start, range_starts, sizeof(uint8_t) * num_ranges);
    memcpy(emul->ignore_end, range_ends, sizeof(uint8_t) * num_ranges);
    return (vmm_pci_entry_t) {
        .cookie = emul, .ioread = pci_cap_emul_read, .iowrite = pci_cap_emul_write
    };
}

#define MAX_CAPS 256

vmm_pci_entry_t vmm_pci_cap_emulation(vmm_pci_entry_t existing, bool enable_msi)
{
    if (enable_msi) {
        pt_cookie = existing.cookie;
    }
    uint32_t value;
    int UNUSED error;
    /* Ensure this is a type 0 device */
    value = 0;
    error = existing.ioread(existing.cookie, PCI_HEADER_TYPE, 1, &value);
    assert(!error);
    assert((value & (~BIT(7))) == PCI_HEADER_TYPE_NORMAL);
    /* Check if it has capability space */
    error = existing.ioread(existing.cookie, PCI_STATUS, 1, &value);
    assert(!error);
    if (!(value & PCI_STATUS_CAP_LIST)) {
        return existing;
    }
    /* First we need to scan the capability space, and detect any PCI caps
     * while we're at it */
    int num_caps;
    uint8_t caps[MAX_CAPS];
    int num_ignore;
    uint8_t ignore_start[2];
    uint8_t ignore_end[2];
    error = existing.ioread(existing.cookie, PCI_CAPABILITY_LIST, 1, &value);
    assert(!error);
    /* Mask off the bottom 2 bits, which are reserved */
    value &= ~MASK(2);
    num_caps = 0;
    num_ignore = 0;
    while (value != 0) {
        uint32_t cap_type = 0;
        error = existing.ioread(existing.cookie, value, 1, &cap_type);
        assert(!error);
        if (cap_type == PCI_CAP_ID_MSI) {
            if (enable_msi) {
                msi_off = value;
                assert(num_caps < MAX_CAPS);
                caps[num_caps] = (uint8_t)value;
                num_caps++;

                /* Enable MSI */
                uint32_t temp;
                error = existing.ioread(existing.cookie, value, 4, &temp);
                printf("MSI off: %x", msi_off);
                printf("64-bit: %d\n", (temp&BIT(23))>>23);
                printf("%d messages supported\n", 1<<((temp >> 17)&0b111));
                printf("MSI %d\n", (temp&BIT(16)>>16));
                // error = existing.iowrite(existing.cookie, value, 4, temp | BIT(16));
            } else {
                assert(num_ignore < 2);
                ignore_start[num_ignore] = value;
                ignore_end[num_ignore] = value + 20;
                num_ignore++;
            }
        } else if (cap_type == PCI_CAP_ID_MSIX) {
            /** @andyb: If MSI works, try make MSIX work... */
            assert(num_ignore < 2);
            ignore_start[num_ignore] = value;
            ignore_end[num_ignore] = value + 8;
            num_ignore++;
        } else {
            assert(num_caps < MAX_CAPS);
            caps[num_caps] = (uint8_t)value;
            num_caps++;
        }
        error = existing.ioread(existing.cookie, value + 1, 1, &value);
        assert(!error);
    }

    if (num_ignore > 0) {
        return vmm_pci_create_cap_emulation(existing, num_caps, caps, num_ignore, ignore_start, ignore_end);
    } else {
        return existing;
    }
}

/**
 * @andyb: This is where we do the MSI cap setup. See for examples:
 * https://wiki.osdev.org/PCI
 * https://github.com/doug65536/dgos/blob/master/kernel/device/pci.cc (pci_set_msi_irq)
 * https://github.com/doug65536/dgos/blob/master/kernel/arch/x86_64/cpu/apic.cc (apic_msi_irq_alloc)
 * 
 * https://github.com/ChaiSoft/ChaiOS/blob/master/Chaikrnl/pciexpress.cpp (PciAllocateMsi)
 * 
 * 
 * order of PCI operations
 * cap rw -> irq rw -> passthrough rw -> pci server or some stupid shit
 * 
 * 
 * notes:
 * guest is supposed to write 0x180 to offset 0x52 with size 2
 */
