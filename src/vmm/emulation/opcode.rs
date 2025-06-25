use crate::{
    info,
    vmm::{
        vcpu::VCpu,
        vmcs::{DescriptorType, EntryControls, Granularity, SegmentRights},
    },
};
use x86::current::vmx::{vmread, vmwrite};
use x86::vmx::vmcs;

const OPCODE_TWO_BYTE_ESCAPE: u8 = 0x0F;
const OPCODE_GROUP_7: u8 = 0x01;
const OPCODE_CLAC: u8 = 0xCA;
const OPCODE_STAC: u8 = 0xCB;
const OPCODE_SYSCALL: u8 = 0x05;

const RFLAGS_AC_BIT: u64 = 1 << 18;

pub fn emulate_opcode(vcpu: &mut VCpu, instruction_bytes: [u8; 16], valid_bytes: u64) -> bool {
    if instruction_bytes[0] != OPCODE_TWO_BYTE_ESCAPE || valid_bytes < 2 {
        return false;
    }

    match instruction_bytes[1] {
        OPCODE_SYSCALL => {
            return emulate_syscall(vcpu);
        }
        _ => {}
    }

    match (instruction_bytes[1], instruction_bytes[2]) {
        (OPCODE_GROUP_7, OPCODE_CLAC) => emulate_clac(vcpu),
        (OPCODE_GROUP_7, OPCODE_STAC) => emulate_stac(vcpu),
        _ => false,
    }
}

fn emulate_syscall(vcpu: &mut VCpu) -> bool {
    let current_rip = unsafe { vmread(vmcs::guest::RIP).unwrap() };
    let return_address = current_rip + 2;

    let rflags = unsafe { vmread(vmcs::guest::RFLAGS).unwrap() };

    vcpu.guest_registers.rcx = return_address;
    vcpu.guest_registers.r11 = rflags;

    let lstar = vcpu.guest_msr.find(0xc0000082).unwrap().data;
    let star = vcpu.guest_msr.find(0xc0000081).unwrap().data;
    let sfmask = vcpu.guest_msr.find(0xc0000084).unwrap().data;

    let cs_selector = (star >> 32) as u16;
    let ss_selector = cs_selector + 8;

    let cs_rights = {
        let mut rights = SegmentRights::default();
        rights.set_rw(true);
        rights.set_dc(false);
        rights.set_executable(true);
        rights.set_desc_type_raw(DescriptorType::Code as u8);
        rights.set_dpl(0);
        rights.set_granularity_raw(Granularity::KByte as u8);
        rights.set_long(true);
        rights.set_db(false);
        rights
    };

    let ss_rights = {
        let mut rights = SegmentRights::default();
        rights.set_rw(true);
        rights.set_dc(false);
        rights.set_executable(false);
        rights.set_desc_type_raw(DescriptorType::Code as u8);
        rights.set_dpl(0);
        rights.set_granularity_raw(Granularity::KByte as u8);
        rights.set_long(false);
        rights.set_db(true);
        rights
    };

    info!("Setting RIP:{:x} to {:x}", current_rip, lstar);
    unsafe {
        // Set segment registers for kernel mode
        vmwrite(vmcs::guest::RIP, lstar).unwrap();
        vmwrite(vmcs::guest::CS_SELECTOR, cs_selector as u64).unwrap();
        vmwrite(vmcs::guest::SS_SELECTOR, ss_selector as u64).unwrap();
        vmwrite(vmcs::guest::CS_BASE, 0).unwrap();
        vmwrite(vmcs::guest::SS_BASE, 0).unwrap();
        vmwrite(vmcs::guest::CS_LIMIT, 0xFFFFFFFF).unwrap();
        vmwrite(vmcs::guest::SS_LIMIT, 0xFFFFFFFF).unwrap();
        vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, cs_rights.0 as u64).unwrap();
        vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, ss_rights.0 as u64).unwrap();

        // Set CR0 and CR4 for Long Mode
        let mut cr0 = vmread(vmcs::guest::CR0).unwrap();
        cr0 |= (1 << 31) | (1 << 0); // Set PG (Paging) and PE (Protection Enable)
        vmwrite(vmcs::guest::CR0, cr0).unwrap();

        let mut cr4 = vmread(vmcs::guest::CR4).unwrap();
        cr4 |= 1 << 5; // Set PAE (Physical Address Extension)
        vmwrite(vmcs::guest::CR4, cr4).unwrap();

        // Set EFER for Long Mode
        let mut efer = vmread(vmcs::guest::IA32_EFER_FULL).unwrap();
        efer |= (1 << 8) | (1 << 10); // Set LME (Long Mode Enable) and LMA (Long Mode Active)
        vmwrite(vmcs::guest::IA32_EFER_FULL, efer).unwrap();

        // Set VM-Entry controls for Long Mode
        let mut entry_ctrls = EntryControls::read();
        entry_ctrls.set_ia32e_mode_guest(true);
        entry_ctrls.write();
    }

    let new_rflags = rflags & !sfmask;
    unsafe {
        vmwrite(vmcs::guest::RFLAGS, new_rflags).unwrap();
    }

    return true;
}

fn emulate_clac(vcpu: &mut VCpu) -> bool {
    if let Err(_) = modify_rflags_ac(false) {
        return false;
    }

    if let Err(_) = vcpu.step_next_inst() {
        return false;
    }

    true
}

fn emulate_stac(vcpu: &mut VCpu) -> bool {
    if let Err(_) = modify_rflags_ac(true) {
        return false;
    }

    if let Err(_) = vcpu.step_next_inst() {
        return false;
    }

    true
}

fn modify_rflags_ac(set: bool) -> x86::vmx::Result<()> {
    unsafe {
        let rflags = vmread(vmcs::guest::RFLAGS)?;
        let new_rflags = if set {
            rflags | RFLAGS_AC_BIT
        } else {
            rflags & !RFLAGS_AC_BIT
        };
        vmwrite(vmcs::guest::RFLAGS, new_rflags)?;
    }
    Ok(())
}
