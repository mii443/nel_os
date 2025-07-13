use crate::{
    info,
    vmm::{
        vcpu::VCpu,
        vmcs::{DescriptorType, EntryControls, Granularity, SegmentRights},
    },
};
use alloc::vec;
use alloc::vec::Vec;
use x86::current::vmx::{vmread, vmwrite};
use x86::vmx::vmcs;

const OPCODE_TWO_BYTE_ESCAPE: u8 = 0x0F;
const OPCODE_GROUP_7: u8 = 0x01;
const OPCODE_CLAC: u8 = 0xCA;
const OPCODE_STAC: u8 = 0xCB;
const OPCODE_SYSCALL: u8 = 0x05;

const RFLAGS_AC_BIT: u64 = 1 << 18;

pub struct OpcodeEmulator {
    pub original_opcode: Option<[u8; 16]>,
    pub replaced_address: Option<u64>,
    pub replaced_size: Option<u64>,
    pub vmcall_control: Option<VmcallControl>,
    pub saved_cs_selector: Option<u16>,
    pub saved_ss_selector: Option<u16>,
    pub saved_gs_selector: Option<u16>,
    pub saved_gs_base: Option<u64>,
    pub saved_rsp: Option<u64>,
}

enum VmcallControl {
    ReturnTo32Bit,
}

impl OpcodeEmulator {
    pub fn new() -> Self {
        OpcodeEmulator {
            original_opcode: None,
            replaced_address: None,
            replaced_size: None,
            vmcall_control: None,
            saved_cs_selector: None,
            saved_ss_selector: None,
            saved_gs_selector: None,
            saved_gs_base: None,
            saved_rsp: None,
        }
    }
}

pub fn emulate_opcode(vcpu: &mut VCpu, instruction_bytes: [u8; 16], valid_bytes: u64) -> bool {
    if instruction_bytes[0] != OPCODE_TWO_BYTE_ESCAPE || valid_bytes < 2 {
        return false;
    }

    match instruction_bytes[1] {
        OPCODE_SYSCALL => {
            return emulate_syscall(vcpu, instruction_bytes);
        }
        _ => {}
    }

    match (instruction_bytes[1], instruction_bytes[2]) {
        (OPCODE_GROUP_7, OPCODE_CLAC) => emulate_clac(vcpu),
        (OPCODE_GROUP_7, OPCODE_STAC) => emulate_stac(vcpu),
        _ => false,
    }
}

pub fn handle_vmcall(vcpu: &mut VCpu, guest_phys_addr: u64) -> bool {
    if let Some(replaced_addr) = vcpu.opcode_emulator.replaced_address {
        if replaced_addr == guest_phys_addr {
            info!("Handling VMCall at {:#x}", guest_phys_addr);

            match vcpu.opcode_emulator.vmcall_control {
                Some(VmcallControl::ReturnTo32Bit) => {
                    if return_to_32_bit(vcpu) {
                        info!("Successfully returned to 32-bit mode.");
                    } else {
                        info!("Failed to return to 32-bit mode.");
                    }
                }
                None => {
                    info!("No VMCall control action defined.");
                }
            }

            if restore_replaced_opcode(vcpu) {
                info!("VMCall handled successfully, original opcode restored.");
            } else {
                info!("Failed to restore original opcode.");
            }
            // Clear saved selectors after handling
            vcpu.opcode_emulator.saved_cs_selector = None;
            vcpu.opcode_emulator.saved_ss_selector = None;
            vcpu.opcode_emulator.saved_gs_selector = None;
            vcpu.opcode_emulator.saved_gs_base = None;
        } else {
            info!(
                "VMCall address mismatch: expected {:#x}, got {:#x}",
                replaced_addr, guest_phys_addr
            );
        }
    } else {
        info!(
            "No opcode replacement found for VMCall at {:#x}",
            guest_phys_addr
        );
    }

    true
}

fn restore_replaced_opcode(vcpu: &mut VCpu) -> bool {
    if let Some(original_opcode) = vcpu.opcode_emulator.original_opcode {
        if let Some(guest_phys_addr) = vcpu.opcode_emulator.replaced_address {
            for (i, &byte) in original_opcode.iter().enumerate() {
                if i >= vcpu.opcode_emulator.replaced_size.unwrap_or(0) as usize {
                    break;
                }
                vcpu.ept.set(guest_phys_addr + i as u64, byte).unwrap();
            }
            vcpu.opcode_emulator.original_opcode = None;
            vcpu.opcode_emulator.replaced_address = None;
            info!(
                "Restoring original opcode at {:#x}: {:?}",
                guest_phys_addr, original_opcode
            );
            return true;
        }
    }
    false
}

fn replace_opcode(vcpu: &mut VCpu, instruction_bytes: [u8; 16], replace: &[u8]) -> bool {
    let replace_len = replace.len();
    if replace_len > 16 {
        return false;
    }

    let mut original_opcode = [0u8; 16];
    original_opcode[..replace_len].copy_from_slice(&instruction_bytes[..replace_len]);

    let rip = unsafe { vmread(vmcs::guest::RIP).unwrap() };
    let guest_phys_addr = vcpu.translate_guest_address(rip).unwrap();
    vcpu.opcode_emulator.original_opcode = Some(original_opcode);
    vcpu.opcode_emulator.replaced_address = Some(guest_phys_addr);
    vcpu.opcode_emulator.replaced_size = Some(replace_len as u64);

    for (i, &byte) in replace.iter().enumerate() {
        vcpu.ept.set(guest_phys_addr + i as u64, byte).unwrap();
    }

    info!(
        "Replacing opcode with: {:?} at {:#x}",
        replace, guest_phys_addr
    );

    true
}

fn return_to_32_bit(vcpu: &mut VCpu) -> bool {
    // 32bitモードへ戻す処理
    info!("Returning to 32-bit mode");
    if !vcpu.emulate_amd {
        return false;
    }

    unsafe {
        // Restore RIP from RCX and RFLAGS from R11 (as SYSRET would do)
        let return_rip = vcpu.guest_registers.rcx;
        let return_rflags = vcpu.guest_registers.r11;

        // Skip past the SYSCALL instruction (2 bytes: 0F 05)
        vmwrite(vmcs::guest::RIP, return_rip + 2).unwrap();
        vmwrite(vmcs::guest::RFLAGS, return_rflags).unwrap();

        // Restore saved segment selectors
        let user_cs_selector = vcpu.opcode_emulator.saved_cs_selector.unwrap_or(0x23);
        let user_ss_selector = vcpu.opcode_emulator.saved_ss_selector.unwrap_or(0x2b);

        // Read current values for logging
        let current_cs_val = vmread(vmcs::guest::CS_SELECTOR).unwrap();
        let current_cs_base = vmread(vmcs::guest::CS_BASE).unwrap();
        let current_cs_limit = vmread(vmcs::guest::CS_LIMIT).unwrap();
        let current_cs_rights = vmread(vmcs::guest::CS_ACCESS_RIGHTS).unwrap();
        let current_ss_val = vmread(vmcs::guest::SS_SELECTOR).unwrap();
        let current_ss_base = vmread(vmcs::guest::SS_BASE).unwrap();
        let current_ss_limit = vmread(vmcs::guest::SS_LIMIT).unwrap();
        let current_ss_rights = vmread(vmcs::guest::SS_ACCESS_RIGHTS).unwrap();

        // Set CS for 32-bit compatibility mode
        vmwrite(vmcs::guest::CS_SELECTOR, user_cs_selector as u64).unwrap();
        vmwrite(vmcs::guest::CS_BASE, 0).unwrap();
        vmwrite(vmcs::guest::CS_LIMIT, 0xFFFFFFFF).unwrap();

        let cs_rights = {
            let mut rights = SegmentRights::default();
            rights.set_rw(true);
            rights.set_dc(false);
            rights.set_executable(true);
            rights.set_desc_type_raw(DescriptorType::Code as u8);
            rights.set_dpl(3); // User mode
            rights.set_granularity_raw(Granularity::KByte as u8);
            rights.set_long(false); // 32-bit compatibility mode
            rights.set_db(true); // 32-bit default
            rights
        };
        vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, cs_rights.0 as u64).unwrap();

        // Set SS for 32-bit compatibility mode
        vmwrite(vmcs::guest::SS_SELECTOR, user_ss_selector as u64).unwrap();
        vmwrite(vmcs::guest::SS_BASE, 0).unwrap();
        vmwrite(vmcs::guest::SS_LIMIT, 0xFFFFFFFF).unwrap();

        let ss_rights = {
            let mut rights = SegmentRights::default();
            rights.set_rw(true);
            rights.set_dc(false);
            rights.set_executable(false);
            rights.set_desc_type_raw(DescriptorType::Code as u8);
            rights.set_dpl(3); // User mode
            rights.set_granularity_raw(Granularity::KByte as u8);
            rights.set_long(false);
            rights.set_db(true);
            rights
        };
        vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, ss_rights.0 as u64).unwrap();

        // Set 32-bit data segment selectors
        vmwrite(vmcs::guest::DS_SELECTOR, 0).unwrap();
        vmwrite(vmcs::guest::ES_SELECTOR, 0).unwrap();
        vmwrite(vmcs::guest::FS_SELECTOR, 0).unwrap();

        // Restore GS selector and base
        let gs_selector = vcpu.opcode_emulator.saved_gs_selector.unwrap_or(0);
        let gs_base = vcpu.opcode_emulator.saved_gs_base.unwrap_or(0);

        let current_gs_val = vmread(vmcs::guest::GS_SELECTOR).unwrap();
        let current_gs_base = vmread(vmcs::guest::GS_BASE).unwrap();

        vmwrite(vmcs::guest::GS_SELECTOR, gs_selector as u64).unwrap();
        vmwrite(vmcs::guest::GS_BASE, gs_base).unwrap();

        // Set segment bases
        vmwrite(vmcs::guest::DS_BASE, 0).unwrap();
        vmwrite(vmcs::guest::ES_BASE, 0).unwrap();
        vmwrite(vmcs::guest::FS_BASE, 0).unwrap();

        // Set segment limits
        vmwrite(vmcs::guest::DS_LIMIT, 0).unwrap();
        vmwrite(vmcs::guest::ES_LIMIT, 0).unwrap();
        vmwrite(vmcs::guest::FS_LIMIT, 0).unwrap();
        vmwrite(vmcs::guest::GS_LIMIT, 0xFFFFFFFF).unwrap();

        // Set segment access rights for null segments (unusable)
        let null_rights = 0x10000; // Unusable bit set
        vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, null_rights).unwrap();
        vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, null_rights).unwrap();
        vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, null_rights).unwrap();

        // Set GS access rights for 32-bit data segment
        let gs_rights = if gs_selector != 0 {
            let mut rights = SegmentRights::default();
            rights.set_rw(true);
            rights.set_dc(false);
            rights.set_executable(false);
            rights.set_desc_type_raw(DescriptorType::Code as u8);
            rights.set_dpl(3); // User mode
            rights.set_granularity_raw(Granularity::KByte as u8);
            rights.set_long(false);
            rights.set_db(true);
            rights.0 as u64
        } else {
            null_rights
        };
        vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, gs_rights).unwrap();

        info!("Restoring user mode segments:");
        info!("  CS: selector={:#x} -> {:#x}, base={:#x} -> {:#x}, limit={:#x} -> {:#x}, rights={:#x} -> {:#x}", 
              current_cs_val, user_cs_selector, current_cs_base, 0, current_cs_limit, 0xFFFFFFFFu64, current_cs_rights, cs_rights.0);
        info!("  SS: selector={:#x} -> {:#x}, base={:#x} -> {:#x}, limit={:#x} -> {:#x}, rights={:#x} -> {:#x}", 
              current_ss_val, user_ss_selector, current_ss_base, 0, current_ss_limit, 0xFFFFFFFFu64, current_ss_rights, ss_rights.0);
        info!(
            "  GS: selector={:#x} -> {:#x}, base={:#x} -> {:#x}",
            current_gs_val, gs_selector, current_gs_base, gs_base
        );

        // Ensure CR0, CR4, and EFER are properly set for compatibility mode
        let mut cr0 = vmread(vmcs::guest::CR0).unwrap();
        cr0 |= (1 << 31) | (1 << 0); // PG and PE bits
        vmwrite(vmcs::guest::CR0, cr0).unwrap();

        let mut cr4 = vmread(vmcs::guest::CR4).unwrap();
        cr4 |= 1 << 5; // PAE bit
        vmwrite(vmcs::guest::CR4, cr4).unwrap();

        let mut efer = vmread(vmcs::guest::IA32_EFER_FULL).unwrap();
        efer |= (1 << 8) | (1 << 10); // LME and LMA bits
        vmwrite(vmcs::guest::IA32_EFER_FULL, efer).unwrap();

        // VM-Entry controls remain in 64-bit mode (Long Mode is still active)
        // Only the CS.L bit determines if we're in compatibility mode

        // Log guest registers that might be important
        info!(
            "Restored to user mode: RIP={:#x}, RFLAGS={:#x}, CS={:#x}, SS={:#x}, GS={:#x}, GS_BASE={:#x}",
            return_rip + 2,
            return_rflags,
            user_cs_selector,
            user_ss_selector,
            gs_selector,
            gs_base
        );
        info!("Guest registers: RAX={:#x}, RCX={:#x}, RDX={:#x}, RSI={:#x}, RDI={:#x}", 
              vcpu.guest_registers.rax,
              vcpu.guest_registers.rcx,
              vcpu.guest_registers.rdx,
              vcpu.guest_registers.rsi,
              vcpu.guest_registers.rdi);
    }

    true
}

fn emulate_syscall(vcpu: &mut VCpu, instruction_bytes: [u8; 16]) -> bool {
    info!("Emulating SYSCALL instruction");
    if !vcpu.emulate_amd {
        return false;
    }

    let current_rip = unsafe { vmread(vmcs::guest::RIP).unwrap() };
    let return_address = current_rip + 2;

    let rflags = unsafe { vmread(vmcs::guest::RFLAGS).unwrap() };

    vcpu.guest_registers.rcx = return_address;
    vcpu.guest_registers.r11 = rflags;

    // Save current segment selectors before changing them
    let current_cs = unsafe { vmread(vmcs::guest::CS_SELECTOR).unwrap() as u16 };
    let current_ss = unsafe { vmread(vmcs::guest::SS_SELECTOR).unwrap() as u16 };
    let current_gs = unsafe { vmread(vmcs::guest::GS_SELECTOR).unwrap() as u16 };
    let current_gs_base = unsafe { vmread(vmcs::guest::GS_BASE).unwrap() };

    // Read all current segment values for logging
    let current_cs_base = unsafe { vmread(vmcs::guest::CS_BASE).unwrap() };
    let current_cs_limit = unsafe { vmread(vmcs::guest::CS_LIMIT).unwrap() };
    let current_cs_rights = unsafe { vmread(vmcs::guest::CS_ACCESS_RIGHTS).unwrap() };
    let current_ss_base = unsafe { vmread(vmcs::guest::SS_BASE).unwrap() };
    let current_ss_limit = unsafe { vmread(vmcs::guest::SS_LIMIT).unwrap() };
    let current_ss_rights = unsafe { vmread(vmcs::guest::SS_ACCESS_RIGHTS).unwrap() };
    let current_gs_limit = unsafe { vmread(vmcs::guest::GS_LIMIT).unwrap() };
    let current_gs_rights = unsafe { vmread(vmcs::guest::GS_ACCESS_RIGHTS).unwrap() };

    info!("Current segments before SYSCALL:");
    info!(
        "  CS: selector={:#x}, base={:#x}, limit={:#x}, rights={:#x}",
        current_cs, current_cs_base, current_cs_limit, current_cs_rights
    );
    info!(
        "  SS: selector={:#x}, base={:#x}, limit={:#x}, rights={:#x}",
        current_ss, current_ss_base, current_ss_limit, current_ss_rights
    );
    info!(
        "  GS: selector={:#x}, base={:#x}, limit={:#x}, rights={:#x}",
        current_gs, current_gs_base, current_gs_limit, current_gs_rights
    );

    vcpu.opcode_emulator.saved_cs_selector = Some(current_cs);
    vcpu.opcode_emulator.saved_ss_selector = Some(current_ss);
    vcpu.opcode_emulator.saved_gs_selector = Some(current_gs);
    vcpu.opcode_emulator.saved_gs_base = Some(current_gs_base);

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
    info!("Setting kernel segments for SYSCALL:");
    info!(
        "  CS: selector={:#x} -> {:#x}, base=0 -> 0, limit={:#x} -> {:#x}, rights={:#x} -> {:#x}",
        current_cs, cs_selector, current_cs_limit, 0xFFFFFFFFu64, current_cs_rights, cs_rights.0
    );
    info!(
        "  SS: selector={:#x} -> {:#x}, base=0 -> 0, limit={:#x} -> {:#x}, rights={:#x} -> {:#x}",
        current_ss, ss_selector, current_ss_limit, 0xFFFFFFFFu64, current_ss_rights, ss_rights.0
    );

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

    let vmcall = vec![0x0f, 0x01, 0xc1];
    replace_opcode(vcpu, instruction_bytes, &vmcall);
    vcpu.opcode_emulator.vmcall_control = Some(VmcallControl::ReturnTo32Bit);

    true
}

fn emulate_clac(vcpu: &mut VCpu) -> bool {
    if modify_rflags_ac(false).is_err() {
        return false;
    }

    if vcpu.step_next_inst().is_err() {
        return false;
    }

    true
}

fn emulate_stac(vcpu: &mut VCpu) -> bool {
    if modify_rflags_ac(true).is_err() {
        return false;
    }

    if vcpu.step_next_inst().is_err() {
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
