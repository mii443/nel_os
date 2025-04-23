#[repr(C)]
#[derive(Default, Debug)]
pub struct GuestRegisters {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub xmm0: M128,
    pub xmm1: M128,
    pub xmm2: M128,
    pub xmm3: M128,
    pub xmm4: M128,
    pub xmm5: M128,
    pub xmm6: M128,
    pub xmm7: M128,
}

#[repr(C, align(16))]
#[derive(Default, Debug)]
pub struct M128 {
    pub data: u128,
}
