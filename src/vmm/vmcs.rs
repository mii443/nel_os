#![allow(non_camel_case_types)]

use bitfield::{bitfield, BitMut};
use x86::{bits64::vmx, vmx::VmFail};
use x86_64::structures::paging::{FrameAllocator, PhysFrame};

use crate::memory::BootInfoFrameAllocator;

macro_rules! vmcs_read {
    ($field_enum: ident, u64) => {
        impl $field_enum {
            pub fn read(self) -> x86::vmx::Result<u64> {
                unsafe { vmx::vmread(self as u32) }
            }
        }
    };
    ($field_enum: ident, $ux: ty) => {
        impl $field_enum {
            pub fn read(self) -> x86::vmx::Result<$ux> {
                unsafe { vmx::vmread(self as u32).map(|v| v as $ux) }
            }
        }
    };
}

macro_rules! vmcs_write {
    ($field_enum: ident, u64) => {
        impl $field_enum {
            pub fn write(self, value: u64) -> x86::vmx::Result<()> {
                unsafe { vmx::vmwrite(self as u32, value) }
            }
        }
    };
    ($field_enum: ident, $ux: ty) => {
        impl $field_enum {
            pub fn write(self, value: $ux) -> x86::vmx::Result<()> {
                unsafe { vmx::vmwrite(self as u32, value as u64) }
            }
        }
    };
}

pub struct Vmcs {
    pub frame: PhysFrame,
}

impl Vmcs {
    pub fn new(frame_allocator: &mut BootInfoFrameAllocator) -> Self {
        let frame = frame_allocator.allocate_frame().unwrap();

        Self { frame }
    }

    pub fn reset(&mut self) -> Result<(), VmFail> {
        let vmcs_addr = self.frame.start_address().as_u64();
        unsafe {
            vmx::vmclear(vmcs_addr)?;
            vmx::vmptrld(vmcs_addr)
        }
    }

    pub fn write_revision_id(&mut self, revision_id: u32, phys_mem_offset: u64) {
        let vmcs_addr = self.frame.start_address().as_u64() + phys_mem_offset;
        unsafe {
            core::ptr::write_volatile(vmcs_addr as *mut u32, revision_id);
        }
    }
}

pub struct InstructionError(pub u32);

impl InstructionError {
    pub fn as_str(&self) -> &str {
        match self.0 {
            0 => "error_not_available",
            1 => "vmcall_in_vmxroot",
            2 => "vmclear_invalid_phys",
            3 => "vmclear_vmxonptr",
            4 => "vmlaunch_nonclear_vmcs",
            5 => "vmresume_nonlaunched_vmcs",
            6 => "vmresume_after_vmxoff",
            7 => "vmentry_invalid_ctrl",
            8 => "vmentry_invalid_host_state",
            9 => "vmptrld_invalid_phys",
            10 => "vmptrld_vmxonp",
            11 => "vmptrld_incorrect_rev",
            12 => "vmrw_unsupported_component",
            13 => "vmw_ro_component",
            15 => "vmxon_in_vmxroot",
            16 => "vmentry_invalid_exec_ctrl",
            17 => "vmentry_nonlaunched_exec_ctrl",
            18 => "vmentry_exec_vmcsptr",
            19 => "vmcall_nonclear_vmcs",
            20 => "vmcall_invalid_exitctl",
            22 => "vmcall_incorrect_msgrev",
            23 => "vmxoff_dualmonitor",
            24 => "vmcall_invalid_smm",
            25 => "vmentry_invalid_execctrl",
            26 => "vmentry_events_blocked",
            28 => "invalid_invept",
            _ => "unknown",
        }
    }

    pub fn read() -> Self {
        let err = VmcsReadOnlyData32::VM_INSTRUCTION_ERROR.read();
        if err.is_err() {
            panic!("Failed to read VM instruction error");
        }
        let err = err.unwrap();
        InstructionError(err)
    }
}

pub struct PinBasedVmExecutionControls(pub u32);

impl PinBasedVmExecutionControls {
    pub fn set_external_interrupt_exiting(&mut self, value: bool) {
        self.0.set_bit(0, value);
    }

    pub fn set_nmi_exiting(&mut self, value: bool) {
        self.0.set_bit(3, value);
    }

    pub fn set_virtual_nmi(&mut self, value: bool) {
        self.0.set_bit(5, value);
    }

    pub fn set_activate_vmx_preemption_timer(&mut self, value: bool) {
        self.0.set_bit(6, value);
    }

    pub fn set_process_posted_interrupts(&mut self, value: bool) {
        self.0.set_bit(7, value);
    }

    pub fn get_external_interrupt_exiting(&self) -> bool {
        self.0 & (1 << 0) != 0
    }

    pub fn get_nmi_exiting(&self) -> bool {
        self.0 & (1 << 3) != 0
    }

    pub fn get_virtual_nmi(&self) -> bool {
        self.0 & (1 << 5) != 0
    }

    pub fn get_activate_vmx_preemption_timer(&self) -> bool {
        self.0 & (1 << 6) != 0
    }

    pub fn get_process_posted_interrupts(&self) -> bool {
        self.0 & (1 << 7) != 0
    }

    pub fn read() -> Self {
        let err = VmcsControl32::PIN_BASED_VM_EXECUTION_CONTROLS.read();
        if err.is_err() {
            panic!("Failed to read Pin Based VM Execution Controls");
        }
        let err = err.unwrap();
        PinBasedVmExecutionControls(err)
    }

    pub fn write(&self) {
        VmcsControl32::PIN_BASED_VM_EXECUTION_CONTROLS
            .write(self.0)
            .expect("Failed to write Pin Based VM Execution Controls");
    }
}

pub struct PrimaryProcessorBasedVmExecutionControls(pub u32);

impl PrimaryProcessorBasedVmExecutionControls {
    pub fn read() -> Self {
        let err = VmcsControl32::PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS.read();
        if err.is_err() {
            panic!("Failed to read Primary Processor Based VM Execution Controls");
        }
        let err = err.unwrap();
        PrimaryProcessorBasedVmExecutionControls(err)
    }

    pub fn write(&self) {
        VmcsControl32::PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS
            .write(self.0)
            .expect("Failed to write Primary Processor Based VM Execution Controls");
    }
}

pub enum DescriptorType {
    System = 0,
    Code = 1,
}

pub enum Granularity {
    Byte = 0,
    KByte = 1,
}

bitfield! {
    pub struct SegmentRights(u32);
    impl Debug;

    pub accessed, set_accessed: 0;
    pub rw, set_rw: 1;
    pub dc, set_dc: 2;
    pub executable, set_executable: 3;
    pub u8, desc_type_raw, set_desc_type_raw: 4, 4;
    pub u8, dpl, set_dpl: 6, 5;
    pub present, set_present: 7;
    pub avl, set_avl: 12;
    pub long, set_long: 13;
    pub u1, db, set_db: 14;
    pub u8, granularity_raw, set_granularity_raw: 15, 15;
    pub unusable, set_unusable: 16;
}

bitfield! {
    pub struct EntryControls(u32);
    impl Debug;

    pub load_debug_controls, set_load_debug_controls: 2;
    pub ia32e_mode_guest, set_ia32e_mode_guest: 9;
    pub entry_smm, set_entry_smm: 10;
    pub deactivate_dualmonitor, set_deactivate_dualmonitor: 11;
    pub load_perf_global_ctrl, set_load_perf_global_ctrl: 13;
    pub load_ia32_pat, set_load_ia32_pat: 14;
    pub load_ia32_efer, set_load_ia32_efer: 15;
    pub load_ia32_bndcfgs, set_load_ia32_bndcfgs: 16;
    pub conceal_vmx_from_pt, set_conceal_vmx_from_pt: 17;
    pub load_rtit_ctl, set_load_rtit_ctl: 18;
    pub load_uinv, set_load_uinv: 19;
    pub load_cet_state, set_load_cet_state: 20;
    pub load_guest_lbr_ctl, set_load_guest_lbr_ctl: 21;
    pub load_pkrs, set_load_pkrs: 22;
}

impl EntryControls {
    pub fn read() -> Self {
        let err = VmcsControl32::VM_ENTRY_CONTROLS.read();
        if err.is_err() {
            panic!("Failed to read VM Entry Controls");
        }
        let err = err.unwrap();
        EntryControls(err)
    }

    pub fn write(&self) {
        VmcsControl32::VM_ENTRY_CONTROLS
            .write(self.0)
            .expect("Failed to write VM Entry Controls");
    }
}

pub enum VmcsControl32 {
    PIN_BASED_VM_EXECUTION_CONTROLS = 0x00004000,
    PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS = 0x00004002,
    EXCEPTION_BITMAP = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
    CR3_TARGET_COUNT = 0x0000400A,
    PRIMARY_VM_EXIT_CONTROLS = 0x0000400C,
    VM_EXIT_MSR_STORE_COUNT = 0x0000400E,
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
    VM_ENTRY_CONTROLS = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
    VM_ENTRY_INTERRUPTION_INFORMATION_FIELD = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
    VM_ENTRY_INSTRUCTION_LENGTH = 0x0000401A,
    TPR_THRESHOLD = 0x0000401C,
    SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS = 0x0000401E,
    PLE_GAP = 0x00004020,
    PLE_WINDOW = 0x00004022,
    INSTRUCTION_TIMEOUT_CONTROL = 0x00004024,
}
vmcs_read!(VmcsControl32, u32);
vmcs_write!(VmcsControl32, u32);

pub enum VmcsReadOnlyData32 {
    VM_INSTRUCTION_ERROR = 0x00004400,
    VM_EXIT_REASON = 0x00004402,
    VM_EXIT_INTERRUPTION_INFORMATION_FIELD = 0x00004404,
    VM_EXIT_INTERRUPTION_ERROR_CODE = 0x00004406,
    IDT_VECTORING_INFORMATION_FIELD = 0x00004408,
    IDT_VECTORING_ERROR_CODE = 0x0000440A,
    VM_EXIT_INSTRUCTION_LENGTH = 0x0000440C,
    VM_EXIT_INSTRUCTION_INFO = 0x0000440E,
}
vmcs_read!(VmcsReadOnlyData32, u32);
