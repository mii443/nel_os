use x86::{
    bits64::vmx::vmwrite,
    controlregs::{cr0, cr3, cr4},
    dtables::{self, DescriptorTablePointer},
    halt,
    msr::{rdmsr, IA32_EFER, IA32_FS_BASE},
    vmx::{vmcs, VmFail},
};

use core::arch::naked_asm;

use crate::{info, memory::BootInfoFrameAllocator};

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
    }

    pub fn setup_exec_ctrls(&mut self) -> Result<(), VmFail> {
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

    pub fn reset_vmcs(&mut self) -> Result<(), VmFail> {
        self.vmcs.reset()
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
