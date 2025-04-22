use x86::{
    bits64::vmx::vmwrite,
    controlregs::{cr0, cr3, cr4},
    dtables::{self, DescriptorTablePointer},
    halt,
    msr::{rdmsr, IA32_EFER, IA32_FS_BASE},
    vmx::{vmcs, VmFail},
};

use core::arch::naked_asm;

use crate::{
    info,
    memory::BootInfoFrameAllocator,
    vmm::vmcs::{DescriptorType, Granularity, SegmentRights},
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

        let mut primary_exec_ctrl = PinBasedVmExecutionControls::read();

        let reserved_bits = if basic_msr & (1 << 55) != 0 {
            unsafe { rdmsr(x86::msr::IA32_VMX_TRUE_PROCBASED_CTLS) }
        } else {
            unsafe { rdmsr(x86::msr::IA32_VMX_PROCBASED_CTLS) }
        };

        primary_exec_ctrl.0 |= (reserved_bits & 0xFFFFFFFF) as u32;
        primary_exec_ctrl.0 &= (reserved_bits >> 32) as u32;

        primary_exec_ctrl.write();

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

            vmwrite(vmcs::guest::CS_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::SS_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::DS_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::ES_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::FS_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::GS_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::TR_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::GDTR_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::IDTR_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::LDTR_LIMIT, u32::MAX as u64)?;

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

            let cs_rights = {
                let mut rights = SegmentRights(0);
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
            vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, cs_rights.0 as u64)?;

            let ds_rights = {
                let mut rights = SegmentRights(0);
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
            vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, ds_rights.0 as u64)?;

            let tr_rights = {
                let mut rights = SegmentRights(0);
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
            vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, tr_rights.0 as u64)?;

            let ldtr_rights = {
                let mut rights = SegmentRights(0);
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
            vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, ldtr_rights.0 as u64)?;

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
        naked_asm!("hlt");
    }

    fn vmexit_handler(&mut self) -> ! {
        info!("VMExit occurred");

        loop {
            unsafe { halt() };
        }
    }

    #[naked]
    unsafe extern "C" fn vmexit(&mut self) -> ! {
        naked_asm!("call {vmexit_handler}", vmexit_handler = sym Self::vmexit_handler);
    }
}
