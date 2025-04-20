use core::arch::asm;
use x86::bits64::rflags::{self, RFlags};
use x86::bits64::vmx;
use x86::controlregs::{cr4, Cr4};
use x86::vmx::{Result, VmFail};
use x86::{msr, msr::rdmsr};
use x86_64::registers::control::Cr0;
use x86_64::structures::paging::{OffsetPageTable, Translate};
use x86_64::VirtAddr;

use crate::info;

#[repr(C, align(4096))]
pub struct Vmxon {
    pub revision_id: u32,
    pub data: [u8; 4092],
}

impl Vmxon {
    pub fn check_vmxon_requirements(&mut self, mapper: OffsetPageTable) -> bool {
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
        let cr0 = unsafe { Cr0::read_raw() };
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
        let vmxon_region = mapper
            .translate_addr(VirtAddr::from_ptr(&self))
            .unwrap()
            .as_u64();
        info!("VMXON region: {:#x}", vmxon_region);
        if vmxon_region & 0xFFF != 0 {
            info!("VMXON region is not aligned to 4K");
            return false;
        }
        info!("VMXON region is aligned to 4K");

        true
    }

    pub fn zeroed() -> Self {
        Vmxon {
            revision_id: 0,
            data: [0; 4092],
        }
    }

    pub fn init(&mut self) {
        self.revision_id = unsafe { rdmsr(x86::msr::IA32_VMX_BASIC) } as u32;
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

    /*pub fn set_cr4_bits() {
        let ia32_vmx_cr4_fixed0 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR4_FIXED0) };
        let ia32_vmx_cr4_fixed1 = unsafe { x86::msr::rdmsr(x86::msr::IA32_VMX_CR4_FIXED1) };

        let mut cr4 = Cr4::read_raw();

        cr4 |= ia32_vmx_cr4_fixed0;
        cr4 &= ia32_vmx_cr4_fixed1;

        unsafe {
            Cr4::write_raw(cr4);
        }
    }*/

    fn vmx_capture_status() -> Result<()> {
        let flags = rflags::read();
        info!("RFlags: {:?}", flags);

        if flags.contains(RFlags::FLAGS_ZF) {
            Err(VmFail::VmFailValid)
        } else if flags.contains(RFlags::FLAGS_CF) {
            Err(VmFail::VmFailInvalid)
        } else {
            Ok(())
        }
    }

    pub unsafe fn vmxon(&mut self) {
        //asm!("vmxon ({0})", in(reg) addr, options(att_syntax));
        x86::bits64::vmx::vmxon(core::ptr::from_mut(self) as u64).unwrap()
    }

    pub fn activate_vmxon(&mut self, mapper: OffsetPageTable) -> core::result::Result<(), ()> {
        info!("activating vmxon...");
        self.setup_vmxon()?;
        info!("VMXON region at virtual address: {:p}", &self.data);
        let phys_addr = mapper
            .translate_addr(VirtAddr::from_ptr(&self))
            .unwrap()
            .as_u64();
        info!("VMXON region at physical address: {:#x}", phys_addr);
        info!("VMXON revision ID: {:#x}", self.revision_id);

        if self.check_vmxon_requirements(mapper) {
            info!("VMXON requirements met");
        } else {
            panic!("VMXON requirements not met");
        }

        unsafe {
            vmx::vmxon(phys_addr).unwrap();
            //self.vmxon();
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
        //Vmxon::set_cr4_bits();
        info!("CR0 and CR4 bits set");

        Ok(())
    }
}
