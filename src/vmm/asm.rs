use core::{arch::global_asm, mem::offset_of};

use super::{register::GuestRegisters, vcpu::VCpu};

#[allow(improper_ctypes)]
extern "C" {
    pub fn asm_vm_entry(vcpu: *mut VCpu) -> u16;
    pub fn asm_vm_entry_resume(vcpu: *mut VCpu) -> u16;
    pub fn guest_entry() -> !;
    pub fn vmexit_handler_asm() -> !;
}

const GUEST_REGS_OFFSET: usize = offset_of!(VCpu, guest_registers);
const LAUNCH_DONE_OFFSET: usize = offset_of!(VCpu, launch_done);

const RAX_OFFSET: usize = offset_of!(GuestRegisters, rax);
const RCX_OFFSET: usize = offset_of!(GuestRegisters, rcx);
const RDX_OFFSET: usize = offset_of!(GuestRegisters, rdx);
const RBX_OFFSET: usize = offset_of!(GuestRegisters, rbx);
const RSI_OFFSET: usize = offset_of!(GuestRegisters, rsi);
const RDI_OFFSET: usize = offset_of!(GuestRegisters, rdi);
const RBP_OFFSET: usize = offset_of!(GuestRegisters, rbp);
const R8_OFFSET: usize = offset_of!(GuestRegisters, r8);
const R9_OFFSET: usize = offset_of!(GuestRegisters, r9);
const R10_OFFSET: usize = offset_of!(GuestRegisters, r10);
const R11_OFFSET: usize = offset_of!(GuestRegisters, r11);
const R12_OFFSET: usize = offset_of!(GuestRegisters, r12);
const R13_OFFSET: usize = offset_of!(GuestRegisters, r13);
const R14_OFFSET: usize = offset_of!(GuestRegisters, r14);
const R15_OFFSET: usize = offset_of!(GuestRegisters, r15);
const XMM0_OFFSET: usize = offset_of!(GuestRegisters, xmm0);
const XMM1_OFFSET: usize = offset_of!(GuestRegisters, xmm1);
const XMM2_OFFSET: usize = offset_of!(GuestRegisters, xmm2);
const XMM3_OFFSET: usize = offset_of!(GuestRegisters, xmm3);
const XMM4_OFFSET: usize = offset_of!(GuestRegisters, xmm4);
const XMM5_OFFSET: usize = offset_of!(GuestRegisters, xmm5);
const XMM6_OFFSET: usize = offset_of!(GuestRegisters, xmm6);
const XMM7_OFFSET: usize = offset_of!(GuestRegisters, xmm7);

global_asm!(
    ".global asm_vm_entry_resume",
    ".type asm_vm_entry_resume, @function",
    "asm_vm_entry_resume:",
    "push rbp",
    "push r15",
    "push r14",
    "push r13",
    "push r12",
    "push rbx",
    "lea rbx, [rdi + {0}]",
    "push rbx",
    "push rdi",
    "lea rdi, [rsp + 8]",
    "call set_host_stack",
    "pop rdi",
    "mov rax, rdi",
    "mov rcx, [rax+{2}]",
    "mov rdx, [rax+{3}]",
    "mov rbx, [rax+{4}]",
    "mov rsi, [rax+{5}]",
    "mov rdi, [rax+{6}]",
    "mov rbp, [rax+{7}]",
    "mov r8, [rax+{8}]",
    "mov r9, [rax+{9}]",
    "mov r10, [rax+{10}]",
    "mov r11, [rax+{11}]",
    "mov r12, [rax+{12}]",
    "mov r13, [rax+{13}]",
    "mov r14, [rax+{14}]",
    "mov r15, [rax+{15}]",
    "movaps xmm0, [rax+{17}]",
    "movaps xmm1, [rax+{18}]",
    "movaps xmm2, [rax+{19}]",
    "movaps xmm3, [rax+{20}]",
    "movaps xmm4, [rax+{21}]",
    "movaps xmm5, [rax+{22}]",
    "movaps xmm6, [rax+{23}]",
    "movaps xmm7, [rax+{24}]",
    "mov rax, [rax+{16}]",
    "vmresume",
    "mov ax, 1",
    "add rsp, 8",
    "pop rbx",
    "pop r12",
    "pop r13",
    "pop r14",
    "pop r15",
    "pop rbp",
    "ret",
    ".size asm_vm_entry_resume, . - asm_vm_entry_resume",

    ".global asm_vm_entry",
    ".type asm_vm_entry, @function",
    "asm_vm_entry:",
    "push rbp",
    "push r15",
    "push r14",
    "push r13",
    "push r12",
    "push rbx",
    "lea rbx, [rdi + {0}]",
    "push rbx",
    "push rdi",
    "lea rdi, [rsp + 8]",
    "call set_host_stack",
    "pop rdi",
    "test byte ptr [rdi + {1}], 1",
    "mov rax, rdi",
    "mov rcx, [rax+{2}]",
    "mov rdx, [rax+{3}]",
    "mov rbx, [rax+{4}]",
    "mov rsi, [rax+{5}]",
    "mov rdi, [rax+{6}]",
    "mov rbp, [rax+{7}]",
    "mov r8, [rax+{8}]",
    "mov r9, [rax+{9}]",
    "mov r10, [rax+{10}]",
    "mov r11, [rax+{11}]",
    "mov r12, [rax+{12}]",
    "mov r13, [rax+{13}]",
    "mov r14, [rax+{14}]",
    "mov r15, [rax+{15}]",
    "mov rax, [rax+{16}]",
    "movaps xmm0, [rax+{17}]",
    "movaps xmm1, [rax+{18}]",
    "movaps xmm2, [rax+{19}]",
    "movaps xmm3, [rax+{20}]",
    "movaps xmm4, [rax+{21}]",
    "movaps xmm5, [rax+{22}]",
    "movaps xmm6, [rax+{23}]",
    "movaps xmm7, [rax+{24}]",
    "vmlaunch",
    "mov ax, 1",
    "add rsp, 8",
    "pop rbx",
    "pop r12",
    "pop r13",
    "pop r14",
    "pop r15",
    "pop rbp",
    "ret",
    ".size asm_vm_entry, . - asm_vm_entry",

    ".global vmexit_handler_asm",
    ".type vmexit_handler_asm, @function",
    "vmexit_handler_asm:",
    "push rax",
    "mov rax, [rsp+8]",
    "pop [rax+{16}]",
    "add rsp, 8",
    "mov [rax+{2}], rcx",
    "mov [rax+{3}], rdx",
    "mov [rax+{4}], rbx",
    "mov [rax+{5}], rsi",
    "mov [rax+{6}], rdi",
    "mov [rax+{7}], rbp",
    "mov [rax+{8}], r8",
    "mov [rax+{9}], r9",
    "mov [rax+{10}], r10",
    "mov [rax+{11}], r11",
    "mov [rax+{12}], r12",
    "mov [rax+{13}], r13",
    "mov [rax+{14}], r14",
    "mov [rax+{15}], r15",
    "movaps [rax+{17}], xmm0",
    "movaps [rax+{18}], xmm1",
    "movaps [rax+{19}], xmm2",
    "movaps [rax+{20}], xmm3",
    "movaps [rax+{21}], xmm4",
    "movaps [rax+{22}], xmm5",
    "movaps [rax+{23}], xmm6",
    "movaps [rax+{24}], xmm7",
    "pop rbx",
    "pop r12",
    "pop r13",
    "pop r14",
    "pop r15",
    "pop rbp",
    "mov rax, 0",
    "ret",
    ".size vmexit_handler_asm, . - vmexit_handler_asm",

    const GUEST_REGS_OFFSET,
    const LAUNCH_DONE_OFFSET,
    const RCX_OFFSET,
    const RDX_OFFSET,
    const RBX_OFFSET,
    const RSI_OFFSET,
    const RDI_OFFSET,
    const RBP_OFFSET,
    const R8_OFFSET,
    const R9_OFFSET,
    const R10_OFFSET,
    const R11_OFFSET,
    const R12_OFFSET,
    const R13_OFFSET,
    const R14_OFFSET,
    const R15_OFFSET,
    const RAX_OFFSET,
    const XMM0_OFFSET,
    const XMM1_OFFSET,
    const XMM2_OFFSET,
    const XMM3_OFFSET,
    const XMM4_OFFSET,
    const XMM5_OFFSET,
    const XMM6_OFFSET,
    const XMM7_OFFSET,
);
