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
