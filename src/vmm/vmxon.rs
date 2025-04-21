use x86::bits64::vmx;
use x86::controlregs::{cr4, Cr4};
use x86::{msr, msr::rdmsr};
use x86_64::registers::control::Cr0;
use x86_64::structures::paging::{FrameAllocator, PhysFrame};

use crate::info;
use crate::memory::BootInfoFrameAllocator;

#[repr(C, align(4096))]
pub struct Vmxon {
    frame: PhysFrame,
}

impl Vmxon {
    pub fn new(frame_allocator: &mut BootInfoFrameAllocator) -> Self {
        let frame = frame_allocator.allocate_frame().unwrap();

        Self { frame }
    }

    pub fn check_vmxon_requirements(&mut self) -> bool {
        info!("");
        info!("Checking VMXON requirements...");
        let cr4 = unsafe { x86::controlregs::cr4() };
        info!("CR4: {:?}", cr4);
        if !cr4.contains(Cr4::CR4_ENABLE_VMX) {
            info!("VMX operation not enabled in CR4");
            return false;
        }
        info!("VMX operation enabled in CR4");

        let ia32_feature_control = unsafe { rdmsr(x86::msr::IA32_FEATURE_CONTROL) };
        info!("IA32_FEATURE_CONTROL: {:#x}", ia32_feature_control);
        if (ia32_feature_control & (1 << 0)) == 0 {
            info!("VMX operation not enabled in IA32_FEATURE_CONTROL");
            return false;
        }
        if (ia32_feature_control & (1 << 2)) == 0 {
            info!("VMX operation not enabled outside of SMX");
            return false;
        }
        info!("VMX operation enabled in IA32_FEATURE_CONTROL");

        let ia32_vmx_cr0_fixed0 = unsafe { rdmsr(x86::msr::IA32_VMX_CR0_FIXED0) };
        let ia32_vmx_cr0_fixed1 = unsafe { rdmsr(x86::msr::IA32_VMX_CR0_FIXED1) };
        info!(
            "IA32_VMX_CR0_FIXED0: {:#x}, IA32_VMX_CR0_FIXED1: {:#x}",
            ia32_vmx_cr0_fixed0, ia32_vmx_cr0_fixed1
        );
        let cr0 = Cr0::read_raw();
        info!("CR0: {:#x}", cr0);
        if (cr0 & ia32_vmx_cr0_fixed0) != ia32_vmx_cr0_fixed0 {
            info!("CR0 does not meet VMX requirements");
            return false;
        }
        if (cr0 & !ia32_vmx_cr0_fixed1) != 0 {
            info!("CR0 does not meet VMX requirements");
            return false;
        }
        info!("CR0 meets VMX requirements");

        let ia32_vmx_cr4_fixed0 = unsafe { rdmsr(x86::msr::IA32_VMX_CR4_FIXED0) };
        let ia32_vmx_cr4_fixed1 = unsafe { rdmsr(x86::msr::IA32_VMX_CR4_FIXED1) };
        info!(
            "IA32_VMX_CR4_FIXED0: {:#x}, IA32_VMX_CR4_FIXED1: {:#x}",
            ia32_vmx_cr4_fixed0, ia32_vmx_cr4_fixed1
        );
        let cr4 = unsafe { x86::controlregs::cr4().bits() as u64 };
        info!("CR4: {:#x}", cr4);
        if (cr4 & ia32_vmx_cr4_fixed0) != ia32_vmx_cr4_fixed0 {
            info!("CR4 does not meet VMX requirements");
            return false;
        }
        if (cr4 & !ia32_vmx_cr4_fixed1) != 0 {
            info!("CR4 does not meet VMX requirements");
            return false;
        }
        info!("CR4 meets VMX requirements");

        // check self data(VMXON region) is aligned to 4K
        let vmxon_region = self.frame.start_address().as_u64();
        info!("VMXON region: {:#x}", vmxon_region);
        if vmxon_region & 0xFFF != 0 {
            info!("VMXON region is not aligned to 4K");
            return false;
        }
        info!("VMXON region is aligned to 4K");

        true
    }

    pub fn init(&mut self, phys_mem_offset: u64) {
        let revision_id = unsafe { rdmsr(x86::msr::IA32_VMX_BASIC) } as u32;
        let vmxon_region = self.frame.start_address().as_u64() + phys_mem_offset;
        info!("VMXON region: {:#x}", vmxon_region);
        info!("VMXON revision ID: {:#x}", revision_id);

        unsafe {
            core::ptr::write_volatile(vmxon_region as *mut u32, revision_id);
        }
    }

    pub fn enable_vmx_operation() {
        unsafe {
            x86::controlregs::cr4_write(cr4() | Cr4::CR4_ENABLE_VMX);
        }
    }

    pub fn adjust_feature_control_msr() -> core::result::Result<(), ()> {
        const VMX_LOCK_BIT: u64 = 1 << 0;
        const VMXON_OUTSIDE_SMX: u64 = 1 << 2;

        let ia32_feature_control = unsafe { x86::msr::rdmsr(x86::msr::IA32_FEATURE_CONTROL) };

        if (ia32_feature_control & VMX_LOCK_BIT) == 0 {
            unsafe {
                x86::msr::wrmsr(
                    x86::msr::IA32_FEATURE_CONTROL,
                    ia32_feature_control | VMXON_OUTSIDE_SMX | VMX_LOCK_BIT,
                );
            }
        }

        Ok(())
    }

    pub fn set_cr0_bits() {
        let ia32_vmx_cr0_fixed0 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED0) };
        let ia32_vmx_cr0_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR0_FIXED1) };

        let mut cr0 = Cr0::read_raw();

        cr0 |= ia32_vmx_cr0_fixed0;
        cr0 &= ia32_vmx_cr0_fixed1;

        unsafe { Cr0::write_raw(cr0) };
    }

    pub fn activate_vmxon(&mut self) -> core::result::Result<(), ()> {
        info!("activating vmxon...");
        self.setup_vmxon()?;

        if self.check_vmxon_requirements() {
            info!("VMXON requirements met");
        } else {
            panic!("VMXON requirements not met");
        }

        unsafe {
            vmx::vmxon(self.frame.start_address().as_u64()).unwrap();
        };
        info!("vmxon success");

        Ok(())
    }

    fn setup_vmxon(&mut self) -> core::result::Result<(), ()> {
        Vmxon::enable_vmx_operation();
        info!("VMX operation enabled");

        Vmxon::adjust_feature_control_msr()?;
        info!("Feature control MSR adjusted");

        Vmxon::set_cr0_bits();
        info!("CR0 bits set");

        Ok(())
    }
}
