#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![feature(new_zeroed_alloc)]
#![test_runner(nel_os::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use bootloader::{entry_point, BootInfo};
use core::arch::asm;
use core::panic::PanicInfo;
use nel_os::{
    allocator, info,
    memory::{self, BootInfoFrameAllocator},
    println,
    vmm::{
        support::{has_intel_cpu, has_vmx_support},
        vmxon::Vmxon,
    },
};
use x86::bits64::rflags;
use x86_64::{
    registers::{control::Cr0Flags, segmentation::Segment},
    VirtAddr,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    nel_os::hlt_loop();
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    nel_os::test_panic_handler(info)
}

entry_point!(kernel_main);

fn kernel_main(boot_info: &'static BootInfo) -> ! {
    println!("NelOS v{}", env!("CARGO_PKG_VERSION"));

    nel_os::init();

    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = unsafe { memory::init(phys_mem_offset) };
    let mut frame_allocator = unsafe { BootInfoFrameAllocator::init(&boot_info.memory_map) };

    allocator::init_heap(&mut mapper, &mut frame_allocator).expect("heap initialization failed");

    if has_intel_cpu() && has_vmx_support() {
        info!("Intel CPU with VMX support detected");
    } else {
        panic!("VMX not supported");
    }

    let mut vmxon = Vmxon::new(&mut frame_allocator);

    vmxon.init(phys_mem_offset.as_u64());
    vmxon.activate_vmxon().unwrap();

    info!("Checking vmlaunch requirements...");
    {
        let mut success = true;
        let cr0 = x86_64::registers::control::Cr0::read();
        if cr0.contains(Cr0Flags::PROTECTED_MODE_ENABLE) {
            info!("Protected mode is enabled");
        } else {
            info!("Protected mode is not enabled");
            success = false;
        }

        let rflags = rflags::read();
        if rflags.contains(rflags::RFlags::FLAGS_VM) {
            info!("VM flag is enabled");
            success = false;
        } else {
            info!("VM flag is not enabled");
        }

        let ia32_efer = unsafe { x86::msr::rdmsr(x86::msr::IA32_EFER) };
        if (ia32_efer & 1 << 10) != 0 {
            info!("IA32_EFER.LMA is enabled");
            let cs = x86_64::registers::segmentation::CS::get_reg().0;
            if cs & 0x1 == 0 {
                info!("CS.L is enabled");
            } else {
                info!("CS.L is not enabled");
                success = false;
            }
        } else {
            info!("IA32_EFER.LMA is not enabled");
        }

        if success {
            info!("vmlaunch requirements are met");
        } else {
            panic!("vmlaunch requirements are not met");
        }
    }

    info!("vmlaunch...");

    unsafe {
        asm!("vmlaunch");
    }

    info!("vmlaunch succeeded");

    #[cfg(test)]
    test_main();

    nel_os::hlt_loop();
}
