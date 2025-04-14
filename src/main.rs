#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(nel_os::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use bootloader::{entry_point, BootInfo};
use core::panic::PanicInfo;
use nel_os::{
    allocator,
    memory::{self, BootInfoFrameAllocator},
    println,
    vmm::support::{has_intel_cpu, has_vmx_support},
};
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

    println!("has_intel_cpu: {}", has_intel_cpu());
    println!("has_vmx_support: {}", has_vmx_support());

    #[cfg(test)]
    test_main();

    nel_os::hlt_loop();
}
