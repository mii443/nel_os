use core::{arch::global_asm, mem::offset_of};

use super::{register::GuestRegisters, vcpu::VCpu};

#[allow(improper_ctypes)]
extern "C" {
    pub fn asm_vm_entry(vcpu: *mut VCpu) -> u16;
    pub fn asm_vmexit_handler() -> !;
}

global_asm!(
    ".global asm_vm_entry",
    ".type asm_vm_entry, @function",
    "asm_vm_entry:", // rdi = *VCpu
    "push rbp",
    "push r15",
    "push r14",
    "push r13",
    "push r12",
    "push rbx",
/*
stack:
+-----+
| RBX |
+-----+
| R12 |
+-----+
| R13 |
+-----+
| R14 |
+-----+
| R15 |
+-----+
| RBP |
+-----+
| RIP |
+-----+

regs:
RDI = *VCpu
*/
    "lea rbx, [rdi + {guest_regs_offset}]", // rbx = *guest_regs
    "push rbx", // push *guest_regs
    "push rdi", // push *VCpu
    "lea rdi, [rsp + 8]", // rdi = rsp + 8 = *guest_regs
    "call set_host_stack",
    "pop rdi", // rdi = *VCpu
    "test byte ptr [rdi + {launch_done_offset}], 1", // flag = launch_done ? 1 : 0
/*
stack:
+-------------+
| *guest_regs |
+-------------+
|     RBX     |
+-------------+
|     R12     |
+-------------+
|     R13     |
+-------------+
|     R14     |
+-------------+
|     R15     |
+-------------+
|     RBP     |
+-------------+
|     RIP     |
+-------------+
regs:
RDI = *VCpu
RBX = *guest_regs
*/
    "mov rax, rbx", // rax = *guest_regs
    "mov rcx, [rax+{reg_offset_rcx}]", // rcx = guest_regs.rcx
    "mov rdx, [rax+{reg_offset_rdx}]", // rdx = guest_regs.rdx
    "mov rbx, [rax+{reg_offset_rbx}]", // rbx = guest_regs.rbx
    "mov rsi, [rax+{reg_offset_rsi}]    ", // rsi = guest_regs.rsi
    "mov rdi, [rax+{reg_offset_rdi}]", // rdi = guest_regs.rdi
    "mov rbp, [rax+{reg_offset_rbp}]", // rbp = guest_regs.rbp
    "mov r8, [rax+{reg_offset_r8}]", // r8 = guest_regs.r8
    "mov r9, [rax+{reg_offset_r9}]", // r9 = guest_regs.r9
    "mov r10, [rax+{reg_offset_r10}]", // r10 = guest_regs.r10
    "mov r11, [rax+{reg_offset_r11}]", // r11 = guest_regs.r11
    "mov r12, [rax+{reg_offset_r12}]", // r12 = guest_regs.r12
    "mov r13, [rax+{reg_offset_r13}]", // r13 = guest_regs.r13
    "mov r14, [rax+{reg_offset_r14}]", // r14 = guest_regs.r14
    "mov r15, [rax+{reg_offset_r15}]", // r15 = guest_regs.r15
    "movaps xmm0, [rax+{reg_offset_xmm0}]", // xmm0 = guest_regs.xmm0
    "movaps xmm1, [rax+{reg_offset_xmm1}]", // xmm1 = guest_regs.xmm1
    "movaps xmm2, [rax+{reg_offset_xmm2}]", // xmm2 = guest_regs.xmm2
    "movaps xmm3, [rax+{reg_offset_xmm3}]", // xmm3 = guest_regs.xmm3
    "movaps xmm4, [rax+{reg_offset_xmm4}]", // xmm4 = guest_regs.xmm4
    "movaps xmm5, [rax+{reg_offset_xmm5}]", // xmm5 = guest_regs.xmm5
    "movaps xmm6, [rax+{reg_offset_xmm6}]", // xmm6 = guest_regs.xmm6
    "movaps xmm7, [rax+{reg_offset_xmm7}]", // xmm7 = guest_regs.xmm7
    "mov rax, [rax+{reg_offset_rax}]", // rax = guest_regs.rax
/*
stack:
+-------------+
| *guest_regs |
+-------------+
|     RBX     |
+-------------+
|     R12     |
+-------------+
|     R13     |
+-------------+
|     R14     |
+-------------+
|     R15     |
+-------------+
|     RBP     |
+-------------+
|     RIP     |
+-------------+
*/
    "jz 2f",
    "vmresume",
    "2:",
    "vmlaunch",
    "mov ax, 1",
    "add rsp, 0x8",
    "pop rbx",
    "pop r12",
    "pop r13",
    "pop r14",
    "pop r15",
    "pop rbp",
    "ret",

    ".size asm_vm_entry, . - asm_vm_entry",

    ".global asm_vmexit_handler",
    ".type asm_vmexit_handler, @function",
    "asm_vmexit_handler:",
    "cli",
/*
stack:
+-------------+
| *guest_regs |
+-------------+
|     RBX     |
+-------------+
|     R12     |
+-------------+
|     R13     |
+-------------+
|     R14     |
+-------------+
|     R15     |
+-------------+
|     RBP     |
+-------------+
|     RIP     |
+-------------+
regs:
RAX = guest CPU's rax
*/
    "push rax",
    "mov rax, qword ptr [rsp + 0x8]", // rax = *guest_regs
/*
stack:
+-------------+
|  guest RAX  |
+-------------+
| *guest_regs |
+-------------+
|     RBX     |
+-------------+
|     R12     |
+-------------+
|     R13     |
+-------------+
|     R14     |
+-------------+
|     R15     |
+-------------+
|     RBP     |
+-------------+
|     RIP     |
+-------------+
*/

    "pop [rax + {reg_offset_rax}]", // guest_regs.rax = guest CPU's rax
    "add rsp, 0x8", // discard *guest_regs
/*
stack:
+-------------+
|     RBX     |
+-------------+
|     R12     |
+-------------+
|     R13     |
+-------------+
|     R14     |
+-------------+
|     R15     |
+-------------+
|     RBP     |
+-------------+
|     RIP     |
+-------------+
*/

    // save rcx, rdx, rbx, rsi, rdi, rbp, r8~15, xmm0~7
    "mov [rax + {reg_offset_rcx}], rcx",
    "mov [rax + {reg_offset_rdx}], rdx",
    "mov [rax + {reg_offset_rbx}], rbx",
    "mov [rax + {reg_offset_rsi}], rsi",
    "mov [rax + {reg_offset_rdi}], rdi",
    "mov [rax + {reg_offset_rbp}], rbp",
    "mov [rax + {reg_offset_r8}], r8",
    "mov [rax + {reg_offset_r9}], r9",
    "mov [rax + {reg_offset_r10}], r10",
    "mov [rax + {reg_offset_r11}], r11",
    "mov [rax + {reg_offset_r12}], r12",
    "mov [rax + {reg_offset_r13}], r13",
    "mov [rax + {reg_offset_r14}], r14",
    "mov [rax + {reg_offset_r15}], r15",
    "movaps [rax + {reg_offset_xmm0}], xmm0",
    "movaps [rax + {reg_offset_xmm1}], xmm1",
    "movaps [rax + {reg_offset_xmm2}], xmm2",
    "movaps [rax + {reg_offset_xmm3}], xmm3",
    "movaps [rax + {reg_offset_xmm4}], xmm4",
    "movaps [rax + {reg_offset_xmm5}], xmm5",
    "movaps [rax + {reg_offset_xmm6}], xmm6",
    "movaps [rax + {reg_offset_xmm7}], xmm7",
    "pop rbx",
    "pop r12",
    "pop r13",
    "pop r14",
    "pop r15",
    "pop rbp",
/*
stack:
+-------------+
|     RIP     |
+-------------+
*/
    "mov rax, 0x0",
    "ret",

    ".size asm_vmexit_handler, . - asm_vmexit_handler",

    guest_regs_offset = const offset_of!(VCpu, guest_registers),
    launch_done_offset = const offset_of!(VCpu, launch_done),
    reg_offset_rax = const offset_of!(GuestRegisters, rax),
    reg_offset_rcx = const offset_of!(GuestRegisters, rcx),
    reg_offset_rdx = const offset_of!(GuestRegisters, rdx),
    reg_offset_rbx = const offset_of!(GuestRegisters, rbx),
    reg_offset_rsi = const offset_of!(GuestRegisters, rsi),
    reg_offset_rdi = const offset_of!(GuestRegisters, rdi),
    reg_offset_rbp = const offset_of!(GuestRegisters, rbp),
    reg_offset_r8 = const offset_of!(GuestRegisters, r8),
    reg_offset_r9 = const offset_of!(GuestRegisters, r9),
    reg_offset_r10 = const offset_of!(GuestRegisters, r10),
    reg_offset_r11 = const offset_of!(GuestRegisters, r11),
    reg_offset_r12 = const offset_of!(GuestRegisters, r12),
    reg_offset_r13 = const offset_of!(GuestRegisters, r13),
    reg_offset_r14 = const offset_of!(GuestRegisters, r14),
    reg_offset_r15 = const offset_of!(GuestRegisters, r15),
    reg_offset_xmm0 = const offset_of!(GuestRegisters, xmm0),
    reg_offset_xmm1 = const offset_of!(GuestRegisters, xmm1),
    reg_offset_xmm2 = const offset_of!(GuestRegisters, xmm2),
    reg_offset_xmm3 = const offset_of!(GuestRegisters, xmm3),
    reg_offset_xmm4 = const offset_of!(GuestRegisters, xmm4),
    reg_offset_xmm5 = const offset_of!(GuestRegisters, xmm5),
    reg_offset_xmm6 = const offset_of!(GuestRegisters, xmm6),
    reg_offset_xmm7 = const offset_of!(GuestRegisters, xmm7),
);
