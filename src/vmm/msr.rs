use core::u64;

use alloc::vec;
use alloc::vec::Vec;
use x86::bits64::vmx::{vmread, vmwrite};
use x86::vmx::vmcs;
use x86_64::structures::paging::{OffsetPageTable, Translate};
use x86_64::{PhysAddr, VirtAddr};

use super::vcpu::VCpu;

type MsrIndex = u32;

const MAX_NUM_ENTS: usize = 512;

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct SavedMsr {
    pub index: MsrIndex,
    pub reserved: u32,
    pub data: u64,
}

impl Default for SavedMsr {
    fn default() -> Self {
        Self {
            index: 0,
            reserved: 0,
            data: 0,
        }
    }
}

#[derive(Debug)]
pub struct ShadowMsr {
    ents: Vec<SavedMsr>,
}

#[derive(Debug)]
pub enum MsrError {
    TooManyEntries,
    BitmapAllocationFailed,
}

impl ShadowMsr {
    pub fn new() -> Self {
        let ents = vec![];

        ShadowMsr { ents }
    }

    pub fn set(&mut self, index: MsrIndex, data: u64) -> Result<(), MsrError> {
        self.set_by_index(index, data)
    }

    pub fn set_by_index(&mut self, index: MsrIndex, data: u64) -> Result<(), MsrError> {
        if let Some(entry) = self.ents.iter_mut().find(|e| e.index == index) {
            entry.data = data;
            return Ok(());
        }

        if self.ents.len() >= MAX_NUM_ENTS {
            return Err(MsrError::TooManyEntries);
        }
        self.ents.push(SavedMsr {
            index,
            reserved: 0,
            data,
        });
        Ok(())
    }

    pub fn saved_ents(&self) -> &[SavedMsr] {
        &self.ents
    }

    pub fn find(&self, index: MsrIndex) -> Option<&SavedMsr> {
        self.ents.iter().find(|e| e.index == index)
    }

    pub fn phys(&self, mapper: &OffsetPageTable<'static>) -> PhysAddr {
        mapper
            .translate_addr(VirtAddr::from_ptr(&self.ents))
            .unwrap()
    }

    pub fn concat(r1: u64, r2: u64) -> u64 {
        ((r1 & 0xFFFFFFFF) << 32) | (r2 & 0xFFFFFFFF)
    }

    pub fn set_ret_val(vcpu: &mut VCpu, val: u64) {
        vcpu.guest_registers.rdx = (val >> 32) as u32 as u64;
        vcpu.guest_registers.rax = val as u32 as u64;
    }

    pub fn shadow_read(vcpu: &mut VCpu, msr_kind: MsrIndex) {
        if let Some(msr) = vcpu.guest_msr.find(msr_kind) {
            Self::set_ret_val(vcpu, msr.data);
        } else {
            panic!("MSR not found");
        }
    }

    pub fn shadow_write(vcpu: &mut VCpu, msr_kind: MsrIndex) {
        let regs = &vcpu.guest_registers;
        if vcpu.guest_msr.find(msr_kind).is_some() {
            vcpu.guest_msr
                .set(msr_kind, Self::concat(regs.rdx, regs.rax))
                .unwrap();
        } else {
            panic!("MSR not found: {:#x}", msr_kind);
        }
    }

    pub fn handle_rdmsr_vmexit(vcpu: &mut VCpu) {
        let msr_kind = vcpu.guest_registers.rcx as u32;

        match msr_kind {
            /*x86::msr::APIC_BASE => {
                // APIC Base Address with APIC disabled (bit 11 = 0)
                // Default base address is 0xFEE00000, BSP bit (bit 8) = 1
                let apic_base = 0xFEE00000 | (1 << 8); // BSP bit set, EN bit cleared
                Self::set_ret_val(vcpu, apic_base);
            }*/
            x86::msr::IA32_EFER => Self::set_ret_val(vcpu, unsafe {
                vmread(vmcs::guest::IA32_EFER_FULL).unwrap()
            }),
            x86::msr::IA32_TIME_STAMP_COUNTER => {
                Self::set_ret_val(vcpu, unsafe { x86::time::rdtsc() })
            }
            x86::msr::IA32_FEATURE_CONTROL => {
                // Lock bit (0) | Enable VMX inside SMX (1) | Enable VMX outside SMX (2)
                Self::set_ret_val(vcpu, 0x5)
            }
            0x48 => Self::set_ret_val(vcpu, 0), // IA32_SPEC_CTRL
            0x122 => Self::set_ret_val(vcpu, 0), // IA32_TSX_CTRL
            0x560 => Self::set_ret_val(vcpu, 0), // IA32_RTIT_OUTPUT_BASE
            0x561 => Self::set_ret_val(vcpu, 0), // IA32_RTIT_OUTPUT_MASK_PTRS
            0x570 => Self::set_ret_val(vcpu, 0), // IA32_RTIT_CTL
            0x571 => Self::set_ret_val(vcpu, 0), // IA32_RTIT_STATUS
            0x572 => Self::set_ret_val(vcpu, 0), // IA32_CR3_MATCH
            0x580 => Self::set_ret_val(vcpu, 0), // IA32_ADDR0_START
            0x581 => Self::set_ret_val(vcpu, 0), // IA32_ADDR0_END
            0x582 => Self::set_ret_val(vcpu, 0), // IA32_ADDR1_START
            0x583 => Self::set_ret_val(vcpu, 0), // IA32_ADDR1_END
            0x584 => Self::set_ret_val(vcpu, 0), // IA32_ADDR2_START
            0x585 => Self::set_ret_val(vcpu, 0), // IA32_ADDR2_END
            0x586 => Self::set_ret_val(vcpu, 0), // IA32_ADDR3_START
            0x587 => Self::set_ret_val(vcpu, 0), // IA32_ADDR3_END
            x86::msr::IA32_FS_BASE => {
                Self::set_ret_val(vcpu, unsafe { vmread(vmcs::guest::FS_BASE).unwrap() })
            }
            x86::msr::IA32_GS_BASE => {
                Self::set_ret_val(vcpu, unsafe { vmread(vmcs::guest::GS_BASE).unwrap() })
            }
            x86::msr::IA32_KERNEL_GSBASE => Self::shadow_read(vcpu, msr_kind),
            x86::msr::IA32_STAR => Self::shadow_read(vcpu, msr_kind),
            x86::msr::IA32_LSTAR => Self::shadow_read(vcpu, msr_kind),
            x86::msr::IA32_CSTAR => Self::shadow_read(vcpu, msr_kind),
            x86::msr::IA32_FMASK => Self::shadow_read(vcpu, msr_kind),
            x86::msr::SYSENTER_CS_MSR => {
                Self::set_ret_val(vcpu, unsafe { vmread(vmcs::guest::IA32_SYSENTER_CS).unwrap() })
            }
            x86::msr::SYSENTER_ESP_MSR => {
                Self::set_ret_val(vcpu, unsafe { vmread(vmcs::guest::IA32_SYSENTER_ESP).unwrap() })
            }
            x86::msr::SYSENTER_EIP_MSR => {
                Self::set_ret_val(vcpu, unsafe { vmread(vmcs::guest::IA32_SYSENTER_EIP).unwrap() })
            }
            0x1b => Self::shadow_read(vcpu, msr_kind),
            0x8b => Self::set_ret_val(vcpu, 0x8701021),
            0xc0011029 => Self::set_ret_val(vcpu, 0x3000310e08202),
            0xc0010000 => Self::set_ret_val(vcpu, 0x130076),
            0xc0010001 => Self::set_ret_val(vcpu, 0),
            0xc0010002 => Self::set_ret_val(vcpu, 0),
            0xc0010003 => Self::set_ret_val(vcpu, 0),
            0xc0010007 => Self::set_ret_val(vcpu, 0),
            0xc0010114 => Self::set_ret_val(vcpu, 0),
            0xc0010117 => Self::set_ret_val(vcpu, 0), // MSR_VM_HSAVE_PA
            0x277 => Self::set_ret_val(vcpu, 0x0007040600070406),
            0xc0000103 => Self::shadow_read(vcpu, msr_kind), // TSC_AUX
            0xd90 => Self::set_ret_val(vcpu, 0), // MSR_C1_PMON_EVNT_SEL0
            0xe1 => Self::set_ret_val(vcpu, 0), // IA32_UMWAIT_CONTROL
            0x1c4 => Self::set_ret_val(vcpu, 0), // Unknown MSR
            0x1c5 => Self::set_ret_val(vcpu, 0), // Unknown MSR
            _ => {
                panic!("Unhandled RDMSR: {:#x}", msr_kind);
            }
        }
    }

    pub fn handle_wrmsr_vmexit(vcpu: &mut VCpu) {
        let regs = &vcpu.guest_registers;
        let value = Self::concat(regs.rdx, regs.rax);
        let msr_kind: MsrIndex = regs.rcx as MsrIndex;

        match msr_kind {
            /*x86::msr::APIC_BASE => {
                // Ignore writes to APIC_BASE MSR - keep APIC disabled
                // Log attempt if enable bit (bit 11) is set
                if (value & (1 << 11)) != 0 {
                    // Guest attempted to enable APIC - ignore
                }
            },*/
            x86::msr::IA32_STAR => Self::shadow_write(vcpu, msr_kind),
            x86::msr::IA32_LSTAR => Self::shadow_write(vcpu, msr_kind),
            x86::msr::IA32_CSTAR => Self::shadow_write(vcpu, msr_kind),
            x86::msr::IA32_TSC_AUX => Self::shadow_write(vcpu, msr_kind),
            x86::msr::IA32_FMASK => Self::shadow_write(vcpu, msr_kind),
            x86::msr::IA32_KERNEL_GSBASE => Self::shadow_write(vcpu, msr_kind),
            x86::msr::MSR_C5_PMON_BOX_CTRL => Self::shadow_write(vcpu, msr_kind),
            x86::msr::SYSENTER_CS_MSR => unsafe {
                vmwrite(vmcs::guest::IA32_SYSENTER_CS, value).unwrap()
            },
            x86::msr::SYSENTER_EIP_MSR => unsafe {
                vmwrite(vmcs::guest::IA32_SYSENTER_EIP, value).unwrap()
            },
            x86::msr::SYSENTER_ESP_MSR => unsafe {
                vmwrite(vmcs::guest::IA32_SYSENTER_ESP, value).unwrap()
            },
            x86::msr::IA32_EFER => unsafe { vmwrite(vmcs::guest::IA32_EFER_FULL, value).unwrap() },
            x86::msr::IA32_FS_BASE => unsafe { vmwrite(vmcs::guest::FS_BASE, value).unwrap() },
            x86::msr::IA32_GS_BASE => unsafe { vmwrite(vmcs::guest::GS_BASE, value).unwrap() },
            0x1b => Self::shadow_write(vcpu, msr_kind),
            0xc0010007 => Self::shadow_write(vcpu, msr_kind),

            _ => {
                panic!("Unhandled WRMSR: {:#x}", msr_kind);
            }
        }
    }
}
