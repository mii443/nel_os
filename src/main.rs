#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(nel_os::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use nel_os::println;

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

#[no_mangle]
pub extern "C" fn _start() -> ! {
    println!("NelOS v{}", env!("CARGO_PKG_VERSION"));

    nel_os::init();

    #[cfg(test)]
    test_main();

    nel_os::hlt_loop();
}
