use lazy_static::lazy_static;
use pic8259::ChainedPics;
use spin::Mutex;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

use crate::{gdt, print, println};

/// Interrupt context containing interrupt information
#[derive(Debug)]
pub struct InterruptContext {
    pub vector: u8,
    pub instruction_pointer: u64,
    pub code_segment: u64,
    pub cpu_flags: u64,
    pub stack_pointer: u64,
    pub stack_segment: u64,
}

/// Subscriber callback function type (simple callback without context)
pub type SubscriberCallback = fn(&InterruptContext);

/// Advanced subscriber callback with user context
pub type AdvancedSubscriberCallback = fn(*mut core::ffi::c_void, &InterruptContext);

/// Interrupt subscriber variants
#[derive(Debug, Clone, Copy)]
pub enum Subscriber {
    Simple {
        callback: SubscriberCallback,
    },
    Advanced {
        callback: AdvancedSubscriberCallback,
        context: *mut core::ffi::c_void,
    },
}

// Safety: We ensure thread safety by using Mutex to protect the subscribers array
unsafe impl Send for Subscriber {}
unsafe impl Sync for Subscriber {}

const MAX_SUBSCRIBERS: usize = 10;

/// Global subscribers array
static SUBSCRIBERS: Mutex<[Option<Subscriber>; MAX_SUBSCRIBERS]> =
    Mutex::new([None; MAX_SUBSCRIBERS]);

/// Subscribe to interrupts with a callback function
pub fn subscribe(callback: SubscriberCallback) -> Result<(), &'static str> {
    let mut subscribers = SUBSCRIBERS.lock();

    for i in 0..MAX_SUBSCRIBERS {
        if subscribers[i].is_none() {
            subscribers[i] = Some(Subscriber::Simple { callback });
            return Ok(());
        }
    }

    Err("Subscriber array full")
}

/// Subscribe to interrupts with an advanced callback that receives user context
pub fn subscribe_with_context(
    callback: AdvancedSubscriberCallback,
    context: *mut core::ffi::c_void,
) -> Result<(), &'static str> {
    let mut subscribers = SUBSCRIBERS.lock();

    for i in 0..MAX_SUBSCRIBERS {
        if subscribers[i].is_none() {
            subscribers[i] = Some(Subscriber::Advanced { callback, context });
            return Ok(());
        }
    }

    Err("Subscriber array full")
}

/// Unsubscribe from interrupts
pub fn unsubscribe(callback: SubscriberCallback) -> Result<(), &'static str> {
    let mut subscribers = SUBSCRIBERS.lock();

    for i in 0..MAX_SUBSCRIBERS {
        if let Some(subscriber) = subscribers[i] {
            match subscriber {
                Subscriber::Simple { callback: cb } => {
                    if cb as *const () == callback as *const () {
                        subscribers[i] = None;
                        return Ok(());
                    }
                }
                _ => {} // Skip advanced subscribers
            }
        }
    }

    Err("Subscriber not found")
}

/// Unsubscribe from interrupts (advanced callback with context)
pub fn unsubscribe_with_context(
    callback: AdvancedSubscriberCallback,
    context: *mut core::ffi::c_void,
) -> Result<(), &'static str> {
    let mut subscribers = SUBSCRIBERS.lock();

    for i in 0..MAX_SUBSCRIBERS {
        if let Some(subscriber) = subscribers[i] {
            match subscriber {
                Subscriber::Advanced {
                    callback: cb,
                    context: ctx,
                } => {
                    if cb as *const () == callback as *const () && ctx == context {
                        subscribers[i] = None;
                        return Ok(());
                    }
                }
                _ => {} // Skip simple subscribers
            }
        }
    }

    Err("Subscriber not found")
}

/// Dispatch interrupt to all subscribers
fn dispatch_to_subscribers(context: &InterruptContext) {
    let subscribers = SUBSCRIBERS.lock();

    for subscriber in subscribers.iter().flatten() {
        match subscriber {
            Subscriber::Simple { callback } => {
                callback(context);
            }
            Subscriber::Advanced {
                callback,
                context: user_context,
            } => {
                callback(*user_context, context);
            }
        }
    }
}

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        unsafe {
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        }
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler);

        idt[InterruptIndex::Timer.as_usize()].set_handler_fn(timer_interrupt_handler);
        idt[InterruptIndex::Keyboard.as_usize()].set_handler_fn(keyboard_interrupt_handler);

        idt
    };
}

pub fn init_idt() {
    IDT.load();
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    let context = InterruptContext {
        vector: 3, // Breakpoint exception vector
        instruction_pointer: stack_frame.instruction_pointer.as_u64(),
        code_segment: stack_frame.code_segment,
        cpu_flags: stack_frame.cpu_flags,
        stack_pointer: stack_frame.stack_pointer.as_u64(),
        stack_segment: stack_frame.stack_segment,
    };

    // Notify subscribers first
    dispatch_to_subscribers(&context);

    println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    let context = InterruptContext {
        vector: 6, // Invalid opcode exception vector
        instruction_pointer: stack_frame.instruction_pointer.as_u64(),
        code_segment: stack_frame.code_segment,
        cpu_flags: stack_frame.cpu_flags,
        stack_pointer: stack_frame.stack_pointer.as_u64(),
        stack_segment: stack_frame.stack_segment,
    };

    // Notify subscribers first
    dispatch_to_subscribers(&context);

    panic!("EXCEPTION: INVALID OPCODE\n{:#?}", stack_frame);
}

use crate::hlt_loop;
use x86_64::structures::idt::PageFaultErrorCode;

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;

    let context = InterruptContext {
        vector: 14, // Page fault exception vector
        instruction_pointer: stack_frame.instruction_pointer.as_u64(),
        code_segment: stack_frame.code_segment,
        cpu_flags: stack_frame.cpu_flags,
        stack_pointer: stack_frame.stack_pointer.as_u64(),
        stack_segment: stack_frame.stack_segment,
    };

    // Notify subscribers first
    dispatch_to_subscribers(&context);

    println!("EXCEPTION: PAGE FAULT");
    println!("Accessed Address: {:?}", Cr2::read());
    println!("Error Code: {:?}", error_code);
    println!("{:#?}", stack_frame);
    hlt_loop();
}

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub static PICS: spin::Mutex<ChainedPics> =
    spin::Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard,
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}

extern "x86-interrupt" fn timer_interrupt_handler(stack_frame: InterruptStackFrame) {
    let context = InterruptContext {
        vector: InterruptIndex::Timer.as_u8(),
        instruction_pointer: stack_frame.instruction_pointer.as_u64(),
        code_segment: stack_frame.code_segment,
        cpu_flags: stack_frame.cpu_flags,
        stack_pointer: stack_frame.stack_pointer.as_u64(),
        stack_segment: stack_frame.stack_segment,
    };

    // Notify subscribers first
    dispatch_to_subscribers(&context);

    // Then handle the interrupt normally
    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
}

extern "x86-interrupt" fn keyboard_interrupt_handler(stack_frame: InterruptStackFrame) {
    use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1};
    use spin::Mutex;
    use x86_64::instructions::port::Port;

    let context = InterruptContext {
        vector: InterruptIndex::Keyboard.as_u8(),
        instruction_pointer: stack_frame.instruction_pointer.as_u64(),
        code_segment: stack_frame.code_segment,
        cpu_flags: stack_frame.cpu_flags,
        stack_pointer: stack_frame.stack_pointer.as_u64(),
        stack_segment: stack_frame.stack_segment,
    };

    // Notify subscribers first
    dispatch_to_subscribers(&context);

    lazy_static! {
        static ref KEYBOARD: Mutex<Keyboard<layouts::Us104Key, ScancodeSet1>> =
            Mutex::new(Keyboard::new(
                ScancodeSet1::new(),
                layouts::Us104Key,
                HandleControl::Ignore
            ));
    }

    let mut keyboard = KEYBOARD.lock();
    let mut port = Port::new(0x60);

    let scancode: u8 = unsafe { port.read() };
    if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
        if let Some(key) = keyboard.process_keyevent(key_event) {
            match key {
                DecodedKey::Unicode(character) => print!("{}", character),
                DecodedKey::RawKey(key) => print!("{:?}", key),
            }
        }
    }

    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}

pub fn example_subscriber(context: &InterruptContext) {
    println!(
        "Subscriber: Interrupt {} occurred at {:#x}",
        context.vector, context.instruction_pointer
    );
}

pub fn vmm_subscriber(vcpu_ptr: *mut core::ffi::c_void, context: &InterruptContext) {
    if !vcpu_ptr.is_null() {
        let vcpu = unsafe { &mut *(vcpu_ptr as *mut crate::vmm::vcpu::VCpu) };

        if 0x20 <= context.vector && context.vector < 0x20 + 16 {
            let irq = context.vector - 0x20;
            vcpu.pending_irq |= 1 << irq;
        }
    }
}

#[test_case]
fn test_breakpoint_exception() {
    x86_64::instructions::interrupts::int3();
}

#[test_case]
fn test_subscriber_functionality() {
    // Test subscribing to interrupts
    let result = subscribe(example_subscriber);
    assert!(result.is_ok());

    // Test that subscriber array has limits
    for _ in 0..MAX_SUBSCRIBERS {
        let _ = subscribe(example_subscriber);
    }
    // This should fail because the array is full
    let result = subscribe(example_subscriber);
    assert!(result.is_err());
}

#[test_case]
fn test_advanced_subscriber_functionality() {
    // Test subscribing with context
    let vcpu_dummy = 0x12345678usize as *mut core::ffi::c_void;
    let result = subscribe_with_context(vmm_subscriber, vcpu_dummy);
    assert!(result.is_ok());

    // Test unsubscribing with context
    let result = unsubscribe_with_context(vmm_subscriber, vcpu_dummy);
    assert!(result.is_ok());

    // Unsubscribing again should fail
    let result = unsubscribe_with_context(vmm_subscriber, vcpu_dummy);
    assert!(result.is_err());
}
