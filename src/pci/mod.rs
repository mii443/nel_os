pub mod device;

use core::fmt;
use x86_64::instructions::port::{Port, PortReadOnly, PortWriteOnly};

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    pub fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    fn to_address(&self, register: u8) -> u32 {
        let bus = self.bus as u32;
        let device = self.device as u32;
        let function = self.function as u32;
        let register = (register & 0xFC) as u32;

        0x80000000 | (bus << 16) | (device << 11) | (function << 8) | register
    }
}

pub fn read_config_u32(addr: PciAddress, register: u8) -> u32 {
    unsafe {
        let mut address_port: Port<u32> = Port::new(CONFIG_ADDRESS);
        let mut data_port: Port<u32> = Port::new(CONFIG_DATA);

        address_port.write(addr.to_address(register));
        data_port.read()
    }
}

pub fn write_config_u32(addr: PciAddress, register: u8, value: u32) {
    unsafe {
        let mut address_port: Port<u32> = Port::new(CONFIG_ADDRESS);
        let mut data_port: Port<u32> = Port::new(CONFIG_DATA);

        address_port.write(addr.to_address(register));
        data_port.write(value);
    }
}

pub fn read_config_u16(addr: PciAddress, register: u8) -> u16 {
    let value = read_config_u32(addr, register & 0xFC);
    let offset = (register & 0x02) * 8;
    (value >> offset) as u16
}

pub fn read_config_u8(addr: PciAddress, register: u8) -> u8 {
    let value = read_config_u32(addr, register & 0xFC);
    let offset = (register & 0x03) * 8;
    (value >> offset) as u8
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeaderType {
    Standard = 0x00,
    PciToPciBridge = 0x01,
    CardBusBridge = 0x02,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassCode {
    pub base: u8,
    pub sub: u8,
    pub interface: u8,
}

impl fmt::Display for ClassCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match (self.base, self.sub) {
            (0x01, 0x00) => "SCSI Controller",
            (0x01, 0x06) => "SATA Controller",
            (0x02, 0x00) => "Ethernet Controller",
            (0x03, 0x00) => "VGA Controller",
            (0x06, 0x00) => "Host Bridge",
            (0x06, 0x01) => "ISA Bridge",
            (0x06, 0x04) => "PCI-to-PCI Bridge",
            (0x0C, 0x03) => "USB Controller",
            _ => "Unknown Device",
        };
        write!(
            f,
            "{} ({:02x}:{:02x}:{:02x})",
            description, self.base, self.sub, self.interface
        )
    }
}

pub fn scan_devices() -> alloc::vec::Vec<device::PciDevice> {
    use alloc::vec::Vec;
    let mut devices = Vec::new();

    for bus in 0..=255 {
        for device in 0..32 {
            let addr = PciAddress::new(bus, device, 0);
            let vendor_id = read_config_u16(addr, 0x00);

            if vendor_id == 0xFFFF {
                continue;
            }

            let header_type = read_config_u8(addr, 0x0E);
            let multifunction = (header_type & 0x80) != 0;

            if let Some(dev) = device::PciDevice::new(addr) {
                devices.push(dev);
            }

            if multifunction {
                for function in 1..8 {
                    let addr = PciAddress::new(bus, device, function);
                    let vendor_id = read_config_u16(addr, 0x00);

                    if vendor_id != 0xFFFF {
                        if let Some(dev) = device::PciDevice::new(addr) {
                            devices.push(dev);
                        }
                    }
                }
            }
        }
    }

    devices
}

pub fn find_device(vendor_id: u16, device_id: u16) -> Option<device::PciDevice> {
    let devices = scan_devices();
    devices
        .into_iter()
        .find(|dev| dev.vendor_id == vendor_id && dev.device_id == device_id)
}

pub fn find_devices_by_class(
    base_class: u8,
    sub_class: Option<u8>,
) -> alloc::vec::Vec<device::PciDevice> {
    let devices = scan_devices();
    devices
        .into_iter()
        .filter(|dev| {
            dev.class.base == base_class
                && (sub_class.is_none() || dev.class.sub == sub_class.unwrap())
        })
        .collect()
}
