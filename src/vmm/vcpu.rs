use x86::{
    bits64::vmx::{vmread, vmwrite},
    controlregs::{cr0, cr3, cr4},
    dtables::{self, DescriptorTablePointer},
    halt,
    msr::{rdmsr, IA32_EFER, IA32_FS_BASE},
    vmx::{vmcs, VmFail},
};
use x86_64::VirtAddr;

use core::arch::{asm, naked_asm};

use crate::{
    info,
    memory::BootInfoFrameAllocator,
    vmm::vmcs::{
        DescriptorType, EntryControls, Granularity, PrimaryExitControls,
        PrimaryProcessorBasedVmExecutionControls, SegmentRights, VmxExitInfo,
    },
};

use super::{
    vmcs::{PinBasedVmExecutionControls, Vmcs},
    vmxon::Vmxon,
};

pub struct VCpu {
    pub vmxon: Vmxon,
    pub vmcs: Vmcs,
    pub phys_mem_offset: u64,
}

const TEMP_STACK_SIZE: usize = 4096;
static mut TEMP_STACK: [u8; TEMP_STACK_SIZE + 0x10] = [0; TEMP_STACK_SIZE + 0x10];

impl VCpu {
    pub fn new(phys_mem_offset: u64, frame_allocator: &mut BootInfoFrameAllocator) -> Self {
        let mut vmxon = Vmxon::new(frame_allocator);
        vmxon.init(phys_mem_offset);
        let vmcs = Vmcs::new(frame_allocator);
        VCpu {
            vmxon,
            vmcs,
            phys_mem_offset,
        }
    }

    pub fn activate(&mut self) {
        self.vmxon.activate_vmxon().unwrap();

        let revision_id = unsafe { rdmsr(x86::msr::IA32_VMX_BASIC) } as u32;
        self.vmcs
            .write_revision_id(revision_id, self.phys_mem_offset);
        self.reset_vmcs().unwrap();
        self.setup_exec_ctrls().unwrap();
        self.setup_entry_ctrls().unwrap();
        self.setup_exit_ctrls().unwrap();
        self.setup_host_state().unwrap();
        self.setup_guest_state().unwrap();
    }

    pub fn setup_exec_ctrls(&mut self) -> Result<(), VmFail> {
        info!("Setting up execution controls");
        let basic_msr = unsafe { rdmsr(x86::msr::IA32_VMX_BASIC) };
        let mut pin_exec_ctrl = PinBasedVmExecutionControls::read();

        let reserved_bits = if basic_msr & (1 << 55) != 0 {
            unsafe { rdmsr(x86::msr::IA32_VMX_TRUE_PINBASED_CTLS) }
        } else {
            unsafe { rdmsr(x86::msr::IA32_VMX_PINBASED_CTLS) }
        };

        pin_exec_ctrl.0 |= (reserved_bits & 0xFFFFFFFF) as u32;
        pin_exec_ctrl.0 &= (reserved_bits >> 32) as u32;

        pin_exec_ctrl.write();

        let mut primary_exec_ctrl = PrimaryProcessorBasedVmExecutionControls::read();

        let reserved_bits = if basic_msr & (1 << 55) != 0 {
            unsafe { rdmsr(x86::msr::IA32_VMX_TRUE_PROCBASED_CTLS) }
        } else {
            unsafe { rdmsr(x86::msr::IA32_VMX_PROCBASED_CTLS) }
        };

        primary_exec_ctrl.0 |= (reserved_bits & 0xFFFFFFFF) as u32;
        primary_exec_ctrl.0 &= (reserved_bits >> 32) as u32;
        primary_exec_ctrl.set_hlt(false);
        primary_exec_ctrl.set_activate_secondary_controls(false);

        primary_exec_ctrl.write();

        Ok(())
    }

    pub fn setup_entry_ctrls(&mut self) -> Result<(), VmFail> {
        info!("Setting up entry controls");

        let basic_msr = unsafe { rdmsr(x86::msr::IA32_VMX_BASIC) };

        let mut entry_ctrl = EntryControls::read();

        let reserved_bits = if basic_msr & (1 << 55) != 0 {
            unsafe { rdmsr(x86::msr::IA32_VMX_TRUE_ENTRY_CTLS) }
        } else {
            unsafe { rdmsr(x86::msr::IA32_VMX_ENTRY_CTLS) }
        };

        entry_ctrl.0 |= (reserved_bits & 0xFFFFFFFF) as u32;
        entry_ctrl.0 &= (reserved_bits >> 32) as u32;
        entry_ctrl.set_ia32e_mode_guest(true);

        entry_ctrl.write();

        Ok(())
    }

    pub fn setup_exit_ctrls(&mut self) -> Result<(), VmFail> {
        info!("Setting up exit controls");

        let basic_msr = unsafe { rdmsr(x86::msr::IA32_VMX_BASIC) };

        let mut exit_ctrl = PrimaryExitControls::read();

        let reserved_bits = if basic_msr & (1 << 55) != 0 {
            unsafe { rdmsr(x86::msr::IA32_VMX_TRUE_EXIT_CTLS) }
        } else {
            unsafe { rdmsr(x86::msr::IA32_VMX_EXIT_CTLS) }
        };

        exit_ctrl.0 |= (reserved_bits & 0xFFFFFFFF) as u32;
        exit_ctrl.0 &= (reserved_bits >> 32) as u32;
        exit_ctrl.set_host_addr_space_size(true);
        exit_ctrl.set_load_ia32_efer(true);

        exit_ctrl.write();

        Ok(())
    }

    pub fn setup_host_state(&mut self) -> Result<(), VmFail> {
        info!("Setting up host state");
        unsafe {
            vmwrite(vmcs::host::CR0, cr0().bits() as u64)?;
            vmwrite(vmcs::host::CR3, cr3())?;
            vmwrite(vmcs::host::CR4, cr4().bits() as u64)?;

            vmwrite(vmcs::host::RIP, Self::vmexit as u64)?;
            vmwrite(
                vmcs::host::RSP,
                VirtAddr::from_ptr(&raw mut TEMP_STACK).as_u64() + TEMP_STACK_SIZE as u64,
            )?;

            vmwrite(
                vmcs::host::ES_SELECTOR,
                x86::segmentation::es().bits() as u64,
            )?;
            vmwrite(
                vmcs::host::CS_SELECTOR,
                x86::segmentation::cs().bits() as u64,
            )?;
            vmwrite(
                vmcs::host::SS_SELECTOR,
                x86::segmentation::ss().bits() as u64,
            )?;
            vmwrite(
                vmcs::host::DS_SELECTOR,
                x86::segmentation::ds().bits() as u64,
            )?;
            vmwrite(
                vmcs::host::FS_SELECTOR,
                x86::segmentation::fs().bits() as u64,
            )?;
            vmwrite(
                vmcs::host::GS_SELECTOR,
                x86::segmentation::gs().bits() as u64,
            )?;
            vmwrite(vmcs::host::FS_BASE, rdmsr(IA32_FS_BASE))?;
            vmwrite(vmcs::host::GS_BASE, rdmsr(IA32_FS_BASE))?;

            let tr = x86::task::tr();
            let mut gdtp = DescriptorTablePointer::<u64>::default();
            let mut idtp = DescriptorTablePointer::<u64>::default();
            dtables::sgdt(&mut gdtp);
            dtables::sidt(&mut idtp);
            vmwrite(vmcs::host::GDTR_BASE, gdtp.base as u64)?;
            vmwrite(vmcs::host::IDTR_BASE, idtp.base as u64)?;
            vmwrite(vmcs::host::TR_SELECTOR, tr.bits() as u64)?;
            vmwrite(vmcs::host::TR_BASE, 0)?;

            vmwrite(vmcs::host::IA32_EFER_FULL, rdmsr(IA32_EFER))?;
        }
        Ok(())
    }

    pub fn setup_guest_state(&mut self) -> Result<(), VmFail> {
        info!("Setting up guest state");

        unsafe {
            vmwrite(vmcs::guest::CR0, cr0().bits() as u64)?;
            vmwrite(vmcs::guest::CR3, cr3())?;
            vmwrite(vmcs::guest::CR4, cr4().bits() as u64)?;

            vmwrite(vmcs::guest::CS_BASE, 0)?;
            vmwrite(vmcs::guest::SS_BASE, 0)?;
            vmwrite(vmcs::guest::DS_BASE, 0)?;
            vmwrite(vmcs::guest::ES_BASE, 0)?;
            vmwrite(vmcs::guest::FS_BASE, 0)?;
            vmwrite(vmcs::guest::GS_BASE, 0)?;
            vmwrite(vmcs::guest::TR_BASE, 0)?;
            vmwrite(vmcs::guest::GDTR_BASE, 0)?;
            vmwrite(vmcs::guest::IDTR_BASE, 0)?;
            vmwrite(vmcs::guest::LDTR_BASE, 0xDEAD00)?;

            vmwrite(vmcs::guest::CS_LIMIT, 0xffff)?;
            vmwrite(vmcs::guest::SS_LIMIT, 0xffff)?;
            vmwrite(vmcs::guest::DS_LIMIT, 0xffff)?;
            vmwrite(vmcs::guest::ES_LIMIT, 0xffff)?;
            vmwrite(vmcs::guest::FS_LIMIT, 0xffff)?;
            vmwrite(vmcs::guest::GS_LIMIT, 0xffff)?;
            vmwrite(vmcs::guest::TR_LIMIT, 0)?;
            vmwrite(vmcs::guest::GDTR_LIMIT, 0)?;
            vmwrite(vmcs::guest::IDTR_LIMIT, 0)?;
            vmwrite(vmcs::guest::LDTR_LIMIT, 0)?;

            vmwrite(
                vmcs::guest::CS_SELECTOR,
                x86::segmentation::cs().bits() as u64,
            )?;
            vmwrite(vmcs::guest::SS_SELECTOR, 0)?;
            vmwrite(vmcs::guest::DS_SELECTOR, 0)?;
            vmwrite(vmcs::guest::ES_SELECTOR, 0)?;
            vmwrite(vmcs::guest::FS_SELECTOR, 0)?;
            vmwrite(vmcs::guest::GS_SELECTOR, 0)?;
            vmwrite(vmcs::guest::TR_SELECTOR, 0)?;
            vmwrite(vmcs::guest::LDTR_SELECTOR, 0)?;

            let cs_right = {
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

            let ds_right = {
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

            let tr_right = {
                let mut rights = SegmentRights::default();
                rights.set_rw(true);
                rights.set_dc(false);
                rights.set_executable(true);
                rights.set_desc_type_raw(DescriptorType::System as u8);
                rights.set_dpl(0);
                rights.set_granularity_raw(Granularity::Byte as u8);
                rights.set_long(false);
                rights.set_db(false);

                rights
            };

            let ldtr_right = {
                let mut rights = SegmentRights::default();
                rights.set_accessed(false);
                rights.set_rw(true);
                rights.set_dc(false);
                rights.set_executable(false);
                rights.set_desc_type_raw(DescriptorType::System as u8);
                rights.set_dpl(0);
                rights.set_granularity_raw(Granularity::Byte as u8);
                rights.set_long(false);
                rights.set_db(false);

                rights
            };

            vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, cs_right.0 as u64)?;
            vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, ds_right.0 as u64)?;
            vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, ds_right.0 as u64)?;
            vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, ds_right.0 as u64)?;
            vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, ds_right.0 as u64)?;
            vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, ds_right.0 as u64)?;
            vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, tr_right.0 as u64)?;
            vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, ldtr_right.0 as u64)?;

            info!("RIP: {:#x}", Self::guest as u64);
            vmwrite(vmcs::guest::RIP, Self::guest as u64)?;
            vmwrite(vmcs::guest::IA32_EFER_FULL, rdmsr(IA32_EFER))?;
            vmwrite(vmcs::guest::RFLAGS, 0x2)?;
            vmwrite(vmcs::guest::LINK_PTR_FULL, u64::MAX)?;
        }

        Ok(())
    }

    pub fn reset_vmcs(&mut self) -> Result<(), VmFail> {
        info!("Resetting VMCS");
        self.vmcs.reset()
    }

    #[naked]
    unsafe extern "C" fn guest() -> ! {
        naked_asm!("2: hlt; jmp 2b");
    }

    fn vmexit_handler(&mut self) -> ! {
        info!("VMExit occurred");

        let raw_info = unsafe { vmread(vmcs::ro::EXIT_REASON) }.unwrap();
        info!("VMExit reason: {:#b}", raw_info);

        let info = VmxExitInfo::read();

        if info.entry_failure() {
            let reason = info.0 & 0xFF;
            match reason {
                33 => {
                    info!("    Reason: VM-entry failure due to invalid guest state");
                }
                34 => {
                    info!("    Reason: VM-entry failure due to MSR loading");
                }
                41 => {
                    info!("    Reason: VM-entry failure due to machine-check event");
                }
                _ => {}
            }
        } else {
            info!(
                "    Reason: {:?} ({})",
                info.get_reason().as_str(),
                info.basic_reason()
            );
        }

        loop {
            unsafe { halt() };
        }
    }

    #[naked]
    unsafe extern "C" fn vmexit(&mut self) -> ! {
        naked_asm!("call {vmexit_handler}", vmexit_handler = sym Self::vmexit_handler);
    }
}
