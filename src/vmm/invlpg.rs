use core::arch::asm;

#[repr(C, packed)]
pub struct InveptDesc {
    eptp: u64,
    reserved: u64,
}

#[repr(C, packed)]
pub struct InvvpidDesc {
    vpid: u16,
    reserved1: u16,
    reserved2: u32,
    linear_address: u64,
}

pub const INVEPT_TYPE_SINGLE_CONTEXT: u64 = 1;
pub const INVEPT_TYPE_ALL_CONTEXT: u64 = 2;

pub const INVVPID_TYPE_INDIVIDUAL_ADDRESS: u64 = 0;
pub const INVVPID_TYPE_SINGLE_CONTEXT: u64 = 1;
pub const INVVPID_TYPE_ALL_CONTEXT: u64 = 2;
pub const INVVPID_TYPE_SINGLE_CONTEXT_RETAINING_GLOBALS: u64 = 3;

/// Invalidate EPT entries
pub unsafe fn invept(invept_type: u64, eptp: u64) -> Result<(), &'static str> {
    let desc = InveptDesc {
        eptp,
        reserved: 0,
    };

    let mut error: u64;
    asm!(
        "xor {0}, {0}",
        "invept {1}, [{2}]",
        "jnc 2f",
        "mov {0}, 1",
        "2:",
        inout(reg) 0u64 => error,
        in(reg) invept_type,
        in(reg) &desc as *const _ as u64,
        options(nostack)
    );

    if error == 0 {
        Ok(())
    } else {
        Err("INVEPT failed")
    }
}

/// Invalidate VPID entries
pub unsafe fn invvpid(invvpid_type: u64, vpid: u16, linear_address: u64) -> Result<(), &'static str> {
    let desc = InvvpidDesc {
        vpid,
        reserved1: 0,
        reserved2: 0,
        linear_address,
    };

    let mut error: u64;
    asm!(
        "xor {0}, {0}",
        "invvpid {1}, [{2}]",
        "jnc 2f",
        "mov {0}, 1",
        "2:",
        inout(reg) 0u64 => error,
        in(reg) invvpid_type,
        in(reg) &desc as *const _ as u64,
        options(nostack)
    );

    if error == 0 {
        Ok(())
    } else {
        Err("INVVPID failed")
    }
}

/// Invalidate all EPT entries for a specific EPTP
pub unsafe fn invept_single_context(eptp: u64) -> Result<(), &'static str> {
    invept(INVEPT_TYPE_SINGLE_CONTEXT, eptp)
}

/// Invalidate all EPT entries for all contexts
pub unsafe fn invept_all_contexts() -> Result<(), &'static str> {
    invept(INVEPT_TYPE_ALL_CONTEXT, 0)
}

/// Invalidate all TLB entries for a specific VPID
pub unsafe fn invvpid_single_context(vpid: u16) -> Result<(), &'static str> {
    invvpid(INVVPID_TYPE_SINGLE_CONTEXT, vpid, 0)
}

/// Invalidate all TLB entries for all VPIDs
pub unsafe fn invvpid_all_contexts() -> Result<(), &'static str> {
    invvpid(INVVPID_TYPE_ALL_CONTEXT, 0, 0)
}

/// Invalidate a specific linear address for a specific VPID
pub unsafe fn invvpid_individual_address(vpid: u16, linear_address: u64) -> Result<(), &'static str> {
    invvpid(INVVPID_TYPE_INDIVIDUAL_ADDRESS, vpid, linear_address)
}