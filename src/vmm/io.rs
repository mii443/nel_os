use x86::io::inb;

use crate::{
    serial,
    vmm::{qual::QualIo, vcpu::VCpu},
};

#[derive(Default)]
pub struct Serial {
    pub ier: u8,
    pub mcr: u8,
}

pub fn handle_io(vcpu: &mut VCpu, qual: QualIo) {
    match qual.direction() {
        0 => {
            handle_io_out(vcpu, qual);
        }
        1 => {
            handle_io_in(vcpu, qual);
        }
        _ => {}
    }
}

pub fn handle_io_in(vcpu: &mut VCpu, qual: QualIo) {
    let regs = &mut vcpu.guest_registers;
    match qual.port() {
        0x0CF8..0x0CFF => {
            regs.rax = 0;
        }
        0xC000..0xCFFF => {} //ignore

        0x03F..0x03FF => handle_serial_in(vcpu, qual),
        _ => {
            panic!("IO in: invalid port: {:#x}", qual.port());
        }
    }
}

pub fn handle_io_out(vcpu: &mut VCpu, qual: QualIo) {
    let regs = &vcpu.guest_registers;
    match qual.port() {
        0x0CF8..0x0CFF => {} //ignore
        0xC000..0xCFFF => {} //ignore
        0x03F8..0x03FF => handle_serial_out(vcpu, qual),
        _ => {
            panic!("IO out: invalid port: {:#x}", qual.port());
        }
    }
}

fn handle_serial_in(vcpu: &mut VCpu, qual: QualIo) {
    let regs = &mut vcpu.guest_registers;
    match qual.port() {
        0x3F8 => regs.rax = unsafe { inb(qual.port()).into() },
        0x3F9 => regs.rax = vcpu.serial.ier as u64,
        0x3FA => regs.rax = unsafe { inb(qual.port()).into() },
        0x3FB => regs.rax = 0,
        0x3FC => regs.rax = vcpu.serial.mcr as u64,
        0x3FD => regs.rax = unsafe { inb(qual.port()).into() },
        0x3FE => regs.rax = unsafe { inb(qual.port()).into() },
        0x3FF => regs.rax = 0,
        _ => {
            panic!("Serial in: invalid port: {:#x}", qual.port());
        }
    }
}

fn handle_serial_out(vcpu: &mut VCpu, qual: QualIo) {
    let regs = &mut vcpu.guest_registers;
    match qual.port() {
        0x3F8 => serial::write_byte(regs.rax as u8),
        0x3F9 => vcpu.serial.ier = regs.rax as u8,
        0x3FA => {}
        0x3FB => {}
        0x3FC => vcpu.serial.mcr = regs.rax as u8,
        0x3FD => {}
        0x3FF => {}
        _ => {
            panic!("Serial out: invalid port: {:#x}", qual.port());
        }
    }
}
