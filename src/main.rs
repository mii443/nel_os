#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![feature(new_zeroed_alloc)]
#![feature(naked_functions)]
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
        vcpu::VCpu,
        vmcs::InstructionError,
    },
};
use x86::bits64::vmx;
use x86_64::VirtAddr;

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

    let mut vcpu = VCpu::new(phys_mem_offset.as_u64(), &mut frame_allocator);
    vcpu.activate();

    info!("vmlaunch...");

    unsafe {
        asm!("cli");
        let vmlaunch = vmx::vmlaunch();

        if vmlaunch.is_err() {
            let error = InstructionError::read();
            let error = error.as_str();
            info!("error: {}", error);
        } else {
            info!("vmlaunch success");
        }
    }

    #[cfg(test)]
    test_main();

    nel_os::hlt_loop();
}
