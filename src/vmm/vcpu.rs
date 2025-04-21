use x86::{msr::rdmsr, vmx::VmFail};

use crate::memory::BootInfoFrameAllocator;

use super::{vmcs::Vmcs, vmxon::Vmxon};

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
    }

    pub fn reset_vmcs(&mut self) -> Result<(), VmFail> {
        self.vmcs.reset()
    }
}
