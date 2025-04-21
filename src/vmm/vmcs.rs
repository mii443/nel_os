use x86::{bits64::vmx, vmx::VmFail};
use x86_64::structures::paging::{FrameAllocator, PhysFrame};

use crate::memory::BootInfoFrameAllocator;

pub struct Vmcs {
    pub frame: PhysFrame,
}

impl Vmcs {
    pub fn new(frame_allocator: &mut BootInfoFrameAllocator) -> Self {
        let frame = frame_allocator.allocate_frame().unwrap();

        Self { frame }
    }

    pub fn reset(&mut self) -> Result<(), VmFail> {
        let vmcs_addr = self.frame.start_address().as_u64();
        unsafe {
            vmx::vmclear(vmcs_addr)?;
            vmx::vmptrld(vmcs_addr)
        }
    }

    pub fn write_revision_id(&mut self, revision_id: u32, phys_mem_offset: u64) {
        let vmcs_addr = self.frame.start_address().as_u64() + phys_mem_offset;
        unsafe {
            core::ptr::write_volatile(vmcs_addr as *mut u32, revision_id);
        }
    }
}

pub struct InstructionError(pub u32);

impl InstructionError {
    pub fn as_str(&self) -> &str {
        match self.0 {
            0 => "error_not_available",
            1 => "vmcall_in_vmxroot",
            2 => "vmclear_invalid_phys",
            3 => "vmclear_vmxonptr",
            4 => "vmlaunch_nonclear_vmcs",
            5 => "vmresume_nonlaunched_vmcs",
            6 => "vmresume_after_vmxoff",
            7 => "vmentry_invalid_ctrl",
            8 => "vmentry_invalid_host_state",
            9 => "vmptrld_invalid_phys",
            10 => "vmptrld_vmxonp",
            11 => "vmptrld_incorrect_rev",
            12 => "vmrw_unsupported_component",
            13 => "vmw_ro_component",
            15 => "vmxon_in_vmxroot",
            16 => "vmentry_invalid_exec_ctrl",
            17 => "vmentry_nonlaunched_exec_ctrl",
            18 => "vmentry_exec_vmcsptr",
            19 => "vmcall_nonclear_vmcs",
            20 => "vmcall_invalid_exitctl",
            22 => "vmcall_incorrect_msgrev",
            23 => "vmxoff_dualmonitor",
            24 => "vmcall_invalid_smm",
            25 => "vmentry_invalid_execctrl",
            26 => "vmentry_events_blocked",
            28 => "invalid_invept",
            _ => "unknown",
        }
    }

    pub fn read() -> Self {
        let err = unsafe { vmx::vmread(0x4400) };
        if err.is_err() {
            panic!("Failed to read VM instruction error");
        }
        let err = err.unwrap();
        InstructionError(err as u32)
    }
}
