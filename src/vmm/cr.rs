use core::convert::TryFrom;

use x86::{
    bits64::vmx::{vmread, vmwrite},
    msr::rdmsr,
    vmx::vmcs,
};

use crate::info;

use super::{
    qual::{AccessType, QualCr, Register},
    vcpu::VCpu,
};

pub fn handle_cr_access(vcpu: &mut VCpu, qual: &QualCr) {
    match AccessType::try_from(qual.access_type().unwrap()).unwrap() {
        AccessType::MovTo => match qual.index() {
            0 | 4 => {
                passthrough_write(vcpu, qual);
                update_ia32e(vcpu);
            }
            _ => panic!("Unsupported CR index: {}", qual.index()),
        },
        AccessType::MovFrom => passthrough_read(vcpu, qual),
        _ => {
            panic!("Unsupported CR access type: {:?}", qual.access_type());
        }
    }
}

fn passthrough_read(vcpu: &mut VCpu, qual: &QualCr) {
    let value = match qual.index() {
        3 => unsafe { vmread(x86::vmx::vmcs::guest::CR3).unwrap() },
        _ => panic!("Unsupported CR index: {}", qual.index()),
    };

    set_value(vcpu, qual, value);
}

fn passthrough_write(vcpu: &mut VCpu, qual: &QualCr) {
    let value = get_value(vcpu, qual);
    match qual.index() {
        0 => unsafe {
            vmwrite(vmcs::guest::CR0, adjust_cr0(value)).unwrap();
            vmwrite(vmcs::control::CR0_READ_SHADOW, value).unwrap();
        },
        4 => unsafe {
            vmwrite(vmcs::guest::CR4, adjust_cr4(value)).unwrap();
            vmwrite(vmcs::control::CR4_READ_SHADOW, value).unwrap();
        },
        _ => {
            panic!("Unsupported CR index: {}", qual.index());
        }
    }
}

pub fn update_ia32e(vcpu: &mut VCpu) {
    let cr0 = unsafe { vmread(x86::vmx::vmcs::guest::CR0).unwrap() };
    let cr4 = unsafe { vmread(x86::vmx::vmcs::guest::CR4).unwrap() };
    let ia32e_enabled = (cr0 & 1 << 31) != 0 && (cr4 & 1 << 5) != 0;

    vcpu.ia32e_enabled = ia32e_enabled;

    let mut entry_ctrl = super::vmcs::EntryControls::read();
    entry_ctrl.set_ia32e_mode_guest(ia32e_enabled);
    entry_ctrl.write();

    let mut efer = unsafe { vmread(x86::vmx::vmcs::guest::IA32_EFER_FULL).unwrap() };

    let lma = (vcpu.ia32e_enabled as u64) << 10;
    if lma != 0 {
        efer |= lma;
    } else {
        efer &= !lma;
    }

    let lme = if cr0 & (1 << 31) != 0 {
        efer & (1 << 10)
    } else {
        efer & !(1 << 8)
    };
    if lme != 0 {
        efer |= lme;
    } else {
        efer &= lme;
    }

    unsafe { vmwrite(x86::vmx::vmcs::guest::IA32_EFER_FULL, efer).unwrap() };
}

pub fn adjust_cr0(value: u64) -> u64 {
    let mut result = value;

    let cr0_fixed0 = unsafe { rdmsr(x86::msr::IA32_VMX_CR0_FIXED0) };
    let cr0_fixed1 = unsafe { rdmsr(x86::msr::IA32_VMX_CR0_FIXED1) };

    result |= cr0_fixed0;
    result &= cr0_fixed1;

    result
}

pub fn adjust_cr4(value: u64) -> u64 {
    let mut result = value;

    let cr4_fixed0 = unsafe { rdmsr(x86::msr::IA32_VMX_CR4_FIXED0) };
    let cr4_fixed1 = unsafe { rdmsr(x86::msr::IA32_VMX_CR4_FIXED1) };

    result |= cr4_fixed0;
    result &= cr4_fixed1;

    result
}

fn set_value(vcpu: &mut VCpu, qual: &QualCr, value: u64) {
    let guest_regs = &mut vcpu.guest_registers;

    match qual.register().unwrap() {
        Register::Rax => guest_regs.rax = value,
        Register::Rcx => guest_regs.rcx = value,
        Register::Rdx => guest_regs.rdx = value,
        Register::Rbx => guest_regs.rbx = value,
        Register::Rbp => guest_regs.rbp = value,
        Register::Rsi => guest_regs.rsi = value,
        Register::Rdi => guest_regs.rdi = value,
        Register::R8 => guest_regs.r8 = value,
        Register::R9 => guest_regs.r9 = value,
        Register::R10 => guest_regs.r10 = value,
        Register::R11 => guest_regs.r11 = value,
        Register::R12 => guest_regs.r12 = value,
        Register::R13 => guest_regs.r13 = value,
        Register::R14 => guest_regs.r14 = value,
        Register::R15 => guest_regs.r15 = value,
        Register::Rsp => unsafe { vmwrite(x86::vmx::vmcs::guest::RSP, value).unwrap() },
    }
}

fn get_value(vcpu: &mut VCpu, qual: &QualCr) -> u64 {
    let guest_regs = &mut vcpu.guest_registers;

    match qual.register().unwrap() {
        Register::Rax => guest_regs.rax,
        Register::Rcx => guest_regs.rcx,
        Register::Rdx => guest_regs.rdx,
        Register::Rbx => guest_regs.rbx,
        Register::Rbp => guest_regs.rbp,
        Register::Rsi => guest_regs.rsi,
        Register::Rdi => guest_regs.rdi,
        Register::R8 => guest_regs.r8,
        Register::R9 => guest_regs.r9,
        Register::R10 => guest_regs.r10,
        Register::R11 => guest_regs.r11,
        Register::R12 => guest_regs.r12,
        Register::R13 => guest_regs.r13,
        Register::R14 => guest_regs.r14,
        Register::R15 => guest_regs.r15,
        Register::Rsp => unsafe { vmread(x86::vmx::vmcs::guest::RSP).unwrap() },
    }
}
