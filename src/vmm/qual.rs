use bitfield::bitfield;
use core::convert::TryFrom;
use core::fmt::Debug;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    MovTo = 0,
    MovFrom = 1,
    Clts = 2,
    Lmsw = 3,
}

impl TryFrom<u8> for AccessType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AccessType::MovTo),
            1 => Ok(AccessType::MovFrom),
            2 => Ok(AccessType::Clts),
            3 => Ok(AccessType::Lmsw),
            _ => Err("Invalid AccessType value"),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LmswOperandType {
    Reg = 0,
    Mem = 1,
}

impl TryFrom<u8> for LmswOperandType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LmswOperandType::Reg),
            1 => Ok(LmswOperandType::Mem),
            _ => Err("Invalid LmswOperandType value"),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rsp = 4,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

impl TryFrom<u8> for Register {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Register::Rax),
            1 => Ok(Register::Rcx),
            2 => Ok(Register::Rdx),
            3 => Ok(Register::Rbx),
            4 => Ok(Register::Rsp),
            5 => Ok(Register::Rbp),
            6 => Ok(Register::Rsi),
            7 => Ok(Register::Rdi),
            8 => Ok(Register::R8),
            9 => Ok(Register::R9),
            10 => Ok(Register::R10),
            11 => Ok(Register::R11),
            12 => Ok(Register::R12),
            13 => Ok(Register::R13),
            14 => Ok(Register::R14),
            15 => Ok(Register::R15),
            _ => Err("Invalid Register value"),
        }
    }
}

bitfield! {
    #[derive(Clone, Copy)]
    pub struct QualCr(u64);
    impl Debug;

    pub u8, index, set_index: 3, 0;
    u8, access_type_raw, set_access_type_raw: 5, 4;
    u8, lmsw_operand_type_raw, set_lmsw_operand_type_raw: 6, 6;
    u8, register_raw, set_register_raw: 11, 8;
    u16, lmsw_source, set_lmsw_source: 31, 16;
}

impl QualCr {
    pub fn access_type(&self) -> Result<AccessType, &'static str> {
        AccessType::try_from(self.access_type_raw())
    }

    pub fn set_access_type(&mut self, val: AccessType) {
        self.set_access_type_raw(val as u8);
    }

    pub fn lmsw_operand_type(&self) -> Result<LmswOperandType, &'static str> {
        LmswOperandType::try_from(self.lmsw_operand_type_raw())
    }

    pub fn set_lmsw_operand_type(&mut self, val: LmswOperandType) {
        self.set_lmsw_operand_type_raw(val as u8);
    }

    pub fn register(&self) -> Result<Register, &'static str> {
        Register::try_from(self.register_raw())
    }

    pub fn set_register(&mut self, val: Register) {
        self.set_register_raw(val as u8);
    }
}
