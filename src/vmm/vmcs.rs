#![allow(non_camel_case_types)]

use core::convert::TryInto;

use bitfield::{bitfield, BitMut};
use numeric_enum_macro::numeric_enum;
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

bitfield! {
    pub struct PrimaryProcessorBasedVmExecutionControls(u32);
    impl Debug;

    pub interrupt_window, set_interrupt_window: 2;
    pub tsc_offsetting, set_tsc_offsetting: 3;
    pub hlt, set_hlt: 7;
    pub invlpg, set_invlpg: 9;
    pub mwait, set_mwait: 10;
    pub rdpmc, set_rdpmc: 11;
    pub rdtsc, set_rdtsc: 12;
    pub cr3load, set_cr3load: 15;
    pub cr3store, set_cr3store: 16;
    pub activate_teritary_controls, set_activate_teritary_controls: 17;
    pub cr8load, set_cr8load: 19;
    pub cr8store, set_cr8store: 20;
    pub use_tpr_shadow, set_use_tpr_shadow: 21;
    pub nmi_window, set_nmi_window: 22;
    pub mov_dr, set_mov_dr: 23;
    pub unconditional_io, set_unconditional_io: 24;
    pub use_io_bitmap, set_use_io_bitmap: 25;
    pub monitor_trap, set_monitor_trap: 27;
    pub use_msr_bitmap, set_use_msr_bitmap: 28;
    pub monitor, set_monitor: 29;
    pub pause, set_pause: 30;
    pub activate_secondary_controls, set_activate_secondary_controls: 31;
}

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

impl Default for SegmentRights {
    fn default() -> Self {
        let mut rights = SegmentRights(0);
        rights.set_accessed(true);
        rights.set_present(true);
        rights.set_avl(false);
        rights.set_long(false);
        rights.set_unusable(false);

        rights
    }
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

bitfield! {
    pub struct PrimaryExitControls(u32);
    impl Debug;

    pub save_debug, set_save_debug: 2;
    pub host_addr_space_size, set_host_addr_space_size: 9;
    pub load_perf_global_ctrl, set_load_perf_global_ctrl: 13;
    pub ack_interrupt_onexit, set_ack_interrupt_onexit: 15;
    pub save_ia32_pat, set_save_ia32_pat: 18;
    pub load_ia32_pat, set_load_ia32_pat: 19;
    pub save_ia32_efer, set_save_ia32_efer: 20;
    pub load_ia32_efer, set_load_ia32_efer: 21;
    pub save_vmx_preemption_timer, set_save_vmx_preemption_timer: 22;
    pub clear_ia32_bndcfgs, set_clear_ia32_bndcfgs: 23;
    pub conceal_vmx_from_pt, set_conceal_vmx_from_pt: 24;
    pub clear_ia32_rtit_ctl, set_clear_ia32_rtit_ctl: 25;
    pub clear_ia32_lbr_ctl, set_clear_ia32_lbr_ctl: 26;
    pub clear_uinv, set_clear_uinv: 27;
    pub load_cet_state, set_load_cet_state: 28;
    pub load_pkrs, set_load_pkrs: 29;
    pub save_perf_global_ctl, set_save_perf_global_ctl: 30;
    pub activate_secondary_controls, set_activate_secondary_controls: 31;
}

impl PrimaryExitControls {
    pub fn read() -> Self {
        let err = VmcsControl32::PRIMARY_VM_EXIT_CONTROLS.read();
        if err.is_err() {
            panic!("Failed to read Primary VM Exit Controls");
        }
        let err = err.unwrap();
        PrimaryExitControls(err)
    }

    pub fn write(&self) {
        VmcsControl32::PRIMARY_VM_EXIT_CONTROLS
            .write(self.0)
            .expect("Failed to write Primary VM Exit Controls");
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

numeric_enum! {
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmxExitReason {
    EXCEPTION = 0,
    EXTERNAL_INTERRUPT = 1,
    TRIPLE_FAULT = 2,
    INIT = 3,
    SIPI = 4,
    IO_SMI = 5,
    OTHER_SMI = 6,
    INTERRUPT_WINDOW = 7,
    NMI_WINDOW = 8,
    TASK_SWITCH = 9,
    CPUID = 10,
    GETSEC = 11,
    HLT = 12,
    INVD = 13,
    INVLPG = 14,
    RDPMC = 15,
    RDTSC = 16,
    RSM = 17,
    VMCALL = 18,
    VMCLEAR = 19,
    VMLAUNCH = 20,
    VMPTRLD = 21,
    VMPTRST = 22,
    VMREAD = 23,
    VMRESUME = 24,
    VMWRITE = 25,
    VMXOFF = 26,
    VMXON = 27,
    CONTROL_REGISTER_ACCESSES = 28,
    MOV_DR = 29,
    IO_INSTRUCTION = 30,
    RDMSR = 31,
    WRMSR = 32,
    VM_ENTRY_FAILURE_INVALID_GUEST_STATE = 33,
    VM_ENTRY_FAILURE_MSR_LOADING = 34,
    MWAIT = 36,
    MONITOR_TRAP_FLAG = 37,
    MONITOR = 39,
    PAUSE = 40,
    VM_ENTRY_FAILURE_MACHINE_CHECK_EVENT = 41,
    TPR_BELOW_THRESHOLD = 43,
    APIC_ACCESS = 44,
    VIRTUALIZED_EOI = 45,
    ACCESS_TO_GDTR_OR_IDTR = 46,
    ACCESS_TO_LDTR_OR_TR = 47,
    EPT_VIOLATION = 48,
    EPT_MISCONFIGURATION = 49,
    INVEPT = 50,
    RDTSCP = 51,
    VMX_PREEMPTION_TIMER_EXPIRED = 52,
    INVVPID = 53,
    WBINVD = 54,
    XSETBV = 55,
    APIC_WRITE = 56,
    RDRAND = 57,
    INVPCID = 58,
    VMFUNC = 59,
    ENCLS = 60,
    RDSEED = 61,
    PAGE_MODIFICATION_LOG_FULL = 62,
    XSAVES = 63,
    XRSTORS = 64,
    PCONFIG = 65,
    SPP_RELATED_EVENT = 66,
    UMWAIT = 67,
    TPAUSE = 68,
    LOADIWKEY = 69,
    ENCLV = 70,
    ENQCMD_PASID_TRANSLATION_FAILURE = 72,
    ENQCMDS_PASID_TRANSLATION_FAILURE = 73,
    BUS_LOCK = 74,
    INSTRUCTION_TIMEOUT = 75,
    SEAMCALL = 76,
    TDCALL = 77,
    RDMSRLIST = 78,
    WRMSRLIST = 79,
}
}

impl VmxExitReason {
    pub fn read() -> Self {
        let reason = VmcsReadOnlyData32::VM_EXIT_REASON.read();
        if reason.is_err() {
            panic!("Failed to read VM exit reason");
        }

        (reason.unwrap() as u16).try_into().unwrap()
    }

    pub fn as_str(&self) -> &'static str {
        use VmxExitReason::*;
        match self {
            EXCEPTION => "Exception or non-maskable interrupt (NMI)",
            EXTERNAL_INTERRUPT => "External interrupt",
            TRIPLE_FAULT => "Triple fault",
            INIT => "INIT signal",
            SIPI => "Start-up IPI (SIPI)",
            IO_SMI => "I/O system-management interrupt (SMI)",
            OTHER_SMI => "Other SMI",
            INTERRUPT_WINDOW => "Interrupt window",
            NMI_WINDOW => "NMI window",
            TASK_SWITCH => "Task switch",
            CPUID => "CPUID instruction execution",
            GETSEC => "GETSEC instruction execution",
            HLT => "HLT instruction execution",
            INVD => "INVD instruction execution",
            INVLPG => "INVLPG instruction execution",
            RDPMC => "RDPMC instruction execution",
            RDTSC => "RDTSC instruction execution",
            RSM => "RSM instruction execution in SMM",
            VMCALL => "VMCALL instruction execution",
            VMCLEAR => "VMCLEAR instruction execution",
            VMLAUNCH => "VMLAUNCH instruction execution",
            VMPTRLD => "VMPTRLD instruction execution",
            VMPTRST => "VMPTRST instruction execution",
            VMREAD => "VMREAD instruction execution",
            VMRESUME => "VMRESUME instruction execution",
            VMWRITE => "VMWRITE instruction execution",
            VMXOFF => "VMXOFF instruction execution",
            VMXON => "VMXON instruction execution",
            CONTROL_REGISTER_ACCESSES => "Control-register accesses",
            MOV_DR => "MOV to or from debug registers",
            IO_INSTRUCTION => "I/O instruction execution",
            RDMSR => "RDMSR instruction execution",
            WRMSR => "WRMSR or WRMSRNS instruction execution",
            VM_ENTRY_FAILURE_INVALID_GUEST_STATE => "VM-entry failure due to invalid guest state",
            VM_ENTRY_FAILURE_MSR_LOADING => "VM-entry failure due to MSR loading",
            MWAIT => "MWAIT instruction execution",
            MONITOR_TRAP_FLAG => "Monitor trap flag",
            MONITOR => "MONITOR instruction execution",
            PAUSE => "PAUSE instruction execution",
            VM_ENTRY_FAILURE_MACHINE_CHECK_EVENT => "VM-entry failure due to machine-check event",
            TPR_BELOW_THRESHOLD => "TPR below threshold",
            APIC_ACCESS => "APIC access",
            VIRTUALIZED_EOI => "Virtualized EOI",
            ACCESS_TO_GDTR_OR_IDTR => "Access to GDTR or IDTR",
            ACCESS_TO_LDTR_OR_TR => "Access to LDTR or TR",
            EPT_VIOLATION => "EPT violation",
            EPT_MISCONFIGURATION => "EPT misconfiguration",
            INVEPT => "INVEPT instruction execution",
            RDTSCP => "RDTSCP instruction execution",
            VMX_PREEMPTION_TIMER_EXPIRED => "VMX-preemption timer expired",
            INVVPID => "INVVPID instruction execution",
            WBINVD => "WBINVD or WBNOINVD instruction execution",
            XSETBV => "XSETBV instruction execution",
            APIC_WRITE => "APIC write",
            RDRAND => "RDRAND instruction execution",
            INVPCID => "INVPCID instruction execution",
            VMFUNC => "VMFUNC instruction execution",
            ENCLS => "ENCLS instruction execution",
            RDSEED => "RDSEED instruction execution",
            PAGE_MODIFICATION_LOG_FULL => "Page-modification log full",
            XSAVES => "XSAVES instruction execution",
            XRSTORS => "XRSTORS instruction execution",
            PCONFIG => "PCONFIG instruction execution",
            SPP_RELATED_EVENT => "SPP-related event",
            UMWAIT => "UMWAIT instruction execution",
            TPAUSE => "TPAUSE instruction execution",
            LOADIWKEY => "LOADIWKEY instruction execution",
            ENCLV => "ENCLV instruction execution",
            ENQCMD_PASID_TRANSLATION_FAILURE => "ENQCMD PASID translation failure",
            ENQCMDS_PASID_TRANSLATION_FAILURE => "ENQCMDS PASID translation failure",
            BUS_LOCK => "Bus lock",
            INSTRUCTION_TIMEOUT => "Instruction timeout",
            SEAMCALL => "SEAMCALL instruction execution",
            TDCALL => "TDCALL instruction execution",
            RDMSRLIST => "RDMSRLIST instruction execution",
            WRMSRLIST => "WRMSRLIST instruction execution",
        }
    }
}

bitfield! {
    pub struct VmxExitInfo(u32);
    impl Debug;

    pub u16, basic_reason, set_basic_reason: 15, 0;
    pub pending_mtf, set_pending_mtf: 26;
    pub exit_vmxroot, set_exit_vmxroot: 27;
    pub entry_failure, set_entry_failure: 31;
}

impl VmxExitInfo {
    pub fn read() -> Self {
        let info = VmcsReadOnlyData32::VM_EXIT_REASON.read();
        if info.is_err() {
            panic!("Failed to read VM exit reason");
        }
        let info = info.unwrap();
        Self(info)
    }

    pub fn get_reason(&self) -> VmxExitReason {
        let reason = self.basic_reason() as u16;
        reason.try_into().unwrap()
    }
}
