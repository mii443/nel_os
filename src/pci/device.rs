use super::{
    read_config_u16, read_config_u32, read_config_u8, write_config_u32, ClassCode, HeaderType,
    PciAddress,
};
use alloc::vec::Vec;
use core::fmt;

#[derive(Debug, Clone)]
pub struct PciDevice {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub command: u16,
    pub status: u16,
    pub class: ClassCode,
    pub header_type: HeaderType,
    pub bars: [Bar; 6],
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Copy)]
pub enum Bar {
    None,
    Memory32 {
        address: u32,
        size: u32,
        prefetchable: bool,
    },
    Memory64 {
        address: u64,
        size: u64,
        prefetchable: bool,
    },
    Io {
        address: u32,
        size: u32,
    },
}

#[derive(Debug, Clone)]
pub struct Capability {
    pub id: u8,
    pub offset: u8,
    pub data: Vec<u8>,
}

// PCI Command Register bits
pub const CMD_IO_SPACE: u16 = 0x0001;
pub const CMD_MEMORY_SPACE: u16 = 0x0002;
pub const CMD_BUS_MASTER: u16 = 0x0004;
pub const CMD_INTERRUPT_DISABLE: u16 = 0x0400;

// PCI Status Register bits
pub const STATUS_INTERRUPT: u16 = 0x0008;
pub const STATUS_CAPABILITIES_LIST: u16 = 0x0010;

// PCI Capability IDs
pub const CAP_MSI: u8 = 0x05;
pub const CAP_MSIX: u8 = 0x11;
pub const CAP_PCIE: u8 = 0x10;

impl PciDevice {
    pub fn new(address: PciAddress) -> Option<Self> {
        let vendor_id = read_config_u16(address, 0x00);
        if vendor_id == 0xFFFF {
            return None;
        }

        let device_id = read_config_u16(address, 0x02);
        let command = read_config_u16(address, 0x04);
        let status = read_config_u16(address, 0x06);

        let class_code = read_config_u8(address, 0x0B);
        let sub_class = read_config_u8(address, 0x0A);
        let interface = read_config_u8(address, 0x09);

        let header_type_raw = read_config_u8(address, 0x0E) & 0x7F;
        let header_type = match header_type_raw {
            0x00 => HeaderType::Standard,
            0x01 => HeaderType::PciToPciBridge,
            0x02 => HeaderType::CardBusBridge,
            _ => return None,
        };

        let mut device = Self {
            address,
            vendor_id,
            device_id,
            command,
            status,
            class: ClassCode {
                base: class_code,
                sub: sub_class,
                interface,
            },
            header_type,
            bars: [Bar::None; 6],
            interrupt_line: read_config_u8(address, 0x3C),
            interrupt_pin: read_config_u8(address, 0x3D),
            capabilities: Vec::new(),
        };

        if header_type == HeaderType::Standard {
            device.read_bars();
        }

        if status & STATUS_CAPABILITIES_LIST != 0 {
            device.read_capabilities();
        }

        Some(device)
    }

    fn read_bars(&mut self) {
        for i in 0..6 {
            let bar_offset = 0x10 + (i * 4) as u8;
            let bar_value = read_config_u32(self.address, bar_offset);

            if bar_value == 0 {
                self.bars[i] = Bar::None;
                continue;
            }

            write_config_u32(self.address, bar_offset, 0xFFFFFFFF);
            let size_mask = read_config_u32(self.address, bar_offset);
            write_config_u32(self.address, bar_offset, bar_value);

            if bar_value & 0x01 != 0 {
                let address = bar_value & 0xFFFFFFFC;
                let size = (!size_mask & 0xFFFFFFFC).wrapping_add(1);
                self.bars[i] = Bar::Io { address, size };
            } else {
                let prefetchable = (bar_value & 0x08) != 0;
                let bar_type = (bar_value >> 1) & 0x03;

                match bar_type {
                    0 => {
                        // 32-bit memory
                        let address = bar_value & 0xFFFFFFF0;
                        let size = (!size_mask & 0xFFFFFFF0).wrapping_add(1);
                        self.bars[i] = Bar::Memory32 {
                            address,
                            size,
                            prefetchable,
                        };
                    }
                    2 => {
                        // 64-bit memory
                        if i < 5 {
                            let bar_high = read_config_u32(self.address, bar_offset + 4);
                            let address =
                                ((bar_high as u64) << 32) | (bar_value & 0xFFFFFFF0) as u64;

                            write_config_u32(self.address, bar_offset + 4, 0xFFFFFFFF);
                            let size_mask_high = read_config_u32(self.address, bar_offset + 4);
                            write_config_u32(self.address, bar_offset + 4, bar_high);

                            let size_mask_full =
                                ((size_mask_high as u64) << 32) | (size_mask & 0xFFFFFFF0) as u64;
                            let size = (!size_mask_full).wrapping_add(1);

                            self.bars[i] = Bar::Memory64 {
                                address,
                                size,
                                prefetchable,
                            };
                            self.bars[i + 1] = Bar::None;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn read_capabilities(&mut self) {
        let mut cap_ptr = read_config_u8(self.address, 0x34) & 0xFC;

        while cap_ptr != 0 {
            let cap_header = read_config_u32(self.address, cap_ptr);
            let cap_id = (cap_header & 0xFF) as u8;
            let next_ptr = ((cap_header >> 8) & 0xFF) as u8;

            // Read capability data based on ID
            let data_size = match cap_id {
                CAP_MSI => 24,  // MSI capability
                CAP_MSIX => 12, // MSI-X capability
                CAP_PCIE => 60, // PCIe capability
                _ => 4,         // Unknown, read minimal
            };

            let mut data = Vec::new();
            for offset in (0..data_size).step_by(4) {
                let value = read_config_u32(self.address, cap_ptr + offset);
                data.extend_from_slice(&value.to_le_bytes());
            }

            self.capabilities.push(Capability {
                id: cap_id,
                offset: cap_ptr,
                data,
            });

            cap_ptr = next_ptr & 0xFC;
        }
    }

    pub fn enable_bus_master(&mut self) {
        self.command |= CMD_BUS_MASTER;
        write_config_u32(self.address, 0x04, self.command as u32);
    }

    pub fn enable_memory_space(&mut self) {
        self.command |= CMD_MEMORY_SPACE;
        write_config_u32(self.address, 0x04, self.command as u32);
    }

    pub fn enable_io_space(&mut self) {
        self.command |= CMD_IO_SPACE;
        write_config_u32(self.address, 0x04, self.command as u32);
    }

    pub fn disable_interrupts(&mut self) {
        self.command |= CMD_INTERRUPT_DISABLE;
        write_config_u32(self.address, 0x04, self.command as u32);
    }

    pub fn find_capability(&self, cap_id: u8) -> Option<&Capability> {
        self.capabilities.iter().find(|cap| cap.id == cap_id)
    }

    pub fn has_msi(&self) -> bool {
        self.find_capability(CAP_MSI).is_some()
    }

    pub fn has_msix(&self) -> bool {
        self.find_capability(CAP_MSIX).is_some()
    }
}

impl fmt::Display for PciDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}.{} [{:04x}:{:04x}] {}",
            self.address.bus,
            self.address.device,
            self.address.function,
            self.vendor_id,
            self.device_id,
            self.class
        )
    }
}
