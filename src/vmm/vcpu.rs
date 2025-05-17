use core::u64;

use x86::{
    bits64::vmx::{vmread, vmwrite},
    controlregs::{cr0, cr3, cr4, Cr0},
    dtables::{self, DescriptorTablePointer},
    msr::{rdmsr, IA32_EFER, IA32_FS_BASE},
    vmx::{vmcs, VmFail},
};
use x86_64::{registers::control::Cr4Flags, structures::paging::OffsetPageTable, VirtAddr};

use crate::{
    info,
    memory::BootInfoFrameAllocator,
    vmm::{
        cpuid, cr, msr,
        qual::QualCr,
        vmcs::{
            DescriptorType, EntryControls, Granularity, PrimaryExitControls,
            PrimaryProcessorBasedVmExecutionControls, SecondaryProcessorBasedVmExecutionControls,
            SegmentRights, VmxExitInfo, VmxExitReason,
        },
    },
};

use super::{
    ept::{EPT, EPTP},
    linux::{self, BootParams, E820Type},
    msr::ShadowMsr,
    register::GuestRegisters,
    vmcs::{InstructionError, PinBasedVmExecutionControls, Vmcs},
    vmxon::Vmxon,
};

#[repr(C)]
pub struct VCpu {
    pub guest_registers: GuestRegisters,
    pub vmxon: Vmxon,
    pub vmcs: Vmcs,
    pub phys_mem_offset: u64,
    pub launch_done: bool,
    pub ept: EPT,
    pub eptp: EPTP,
    pub host_msr: ShadowMsr,
    pub guest_msr: ShadowMsr,
    pub ia32e_enabled: bool,
}

const TEMP_STACK_SIZE: usize = 4096;
static mut TEMP_STACK: [u8; TEMP_STACK_SIZE + 0x10] = [0; TEMP_STACK_SIZE + 0x10];

impl VCpu {
    pub fn new(phys_mem_offset: u64, frame_allocator: &mut BootInfoFrameAllocator) -> Self {
        let mut vmxon = Vmxon::new(frame_allocator);
        vmxon.init(phys_mem_offset);
        let vmcs = Vmcs::new(frame_allocator);
        let ept = EPT::new(frame_allocator);
        let eptp = EPTP::new(&ept.root_table);

        VCpu {
            vmxon,
            vmcs,
            phys_mem_offset,
            guest_registers: GuestRegisters::default(),
            launch_done: false,
            ept,
            eptp,
            host_msr: ShadowMsr::new(),
            guest_msr: ShadowMsr::new(),
            ia32e_enabled: false,
        }
    }

    pub fn activate(
        &mut self,
        frame_allocator: &mut BootInfoFrameAllocator,
        mapper: &OffsetPageTable<'static>,
    ) {
        self.vmxon.activate_vmxon().unwrap();

        let revision_id = unsafe { rdmsr(x86::msr::IA32_VMX_BASIC) } as u32;
        self.vmcs
            .write_revision_id(revision_id, self.phys_mem_offset);
        self.reset_vmcs().unwrap();
        self.setup_exec_ctrls().unwrap();
        self.setup_entry_ctrls().unwrap();
        self.setup_exit_ctrls().unwrap();
        self.setup_host_state().unwrap();
        self.setup_guest_state().unwrap();
        self.setup_guest_memory(frame_allocator);
        self.register_msrs(&mapper);
    }

    pub fn load_kernel(&mut self, kernel: &[u8]) {
        info!("Loading kernel into guest memory");
        let guest_mem_size = 100 * 1024 * 1024;
        let mut bp = BootParams::from_bytes(kernel).unwrap();
        bp.e820_entries = 0;

        bp.hdr.type_of_loader = 0xFF;
        bp.hdr.ext_loader_ver = 0;
        bp.hdr.loadflags.set_loaded_high(true);
        bp.hdr.loadflags.set_can_use_heap(true);
        bp.hdr.heap_end_ptr = (linux::LAYOUT_BOOTPARAM - 0x200) as u16;
        bp.hdr.loadflags.set_keep_segments(true);
        bp.hdr.cmd_line_ptr = linux::LAYOUT_CMDLINE as u32;
        bp.hdr.vid_mode = 0xFFFF;

        bp.add_e820_entry(0, linux::LAYOUT_KERNEL_BASE, E820Type::Ram);
        bp.add_e820_entry(
            linux::LAYOUT_KERNEL_BASE,
            guest_mem_size - linux::LAYOUT_KERNEL_BASE,
            E820Type::Ram,
        );

        let cmdline_max_size = if bp.hdr.cmdline_size < 256 {
            bp.hdr.cmdline_size
        } else {
            256
        };

        let cmdline_start = linux::LAYOUT_CMDLINE as u64;
        let cmdline_end = cmdline_start + cmdline_max_size as u64;
        self.ept.set_range(cmdline_start, cmdline_end, 0).unwrap();
        let cmdline_val = "console=ttyS0 earlyprintk=serial nokaslr";
        let cmdline_bytes = cmdline_val.as_bytes();
        for (i, &byte) in cmdline_bytes.iter().enumerate() {
            self.ept.set(cmdline_start + i as u64, byte).unwrap();
        }

        let bp_bytes = unsafe {
            core::slice::from_raw_parts(
                &bp as *const BootParams as *const u8,
                core::mem::size_of::<BootParams>(),
            )
        };
        self.load_image(bp_bytes, linux::LAYOUT_BOOTPARAM as usize);

        let code_offset = bp.hdr.get_protected_code_offset();
        let code_size = kernel.len() - code_offset;
        self.load_image(
            &kernel[code_offset..code_offset + code_size],
            linux::LAYOUT_KERNEL_BASE as usize,
        );

        info!("Kernel loaded into guest memory");
    }

    pub fn load_image(&mut self, image: &[u8], addr: usize) {
        for (i, &byte) in image.iter().enumerate() {
            let gpa = addr + i;
            self.ept.set(gpa as u64, byte).unwrap();
        }
    }

    pub fn setup_guest_memory(&mut self, frame_allocator: &mut BootInfoFrameAllocator) {
        let mut pages = 100;
        let mut gpa = 0;

        info!("Setting up guest memory...");
        while pages > 0 {
            let frame = frame_allocator
                .allocate_2mib_frame()
                .expect("Failed to allocate frame");
            let hpa = frame.start_address().as_u64();

            self.ept.map_2m(gpa, hpa, frame_allocator).unwrap();
            gpa += (4 * 1024) << 9;
            pages -= 1;
        }
        info!("Guest memory setup complete");

        self.load_kernel(linux::BZIMAGE);

        let eptp = EPTP::new(&self.ept.root_table);
        unsafe { vmwrite(vmcs::control::EPTP_FULL, eptp.0).unwrap() };
    }

    pub fn register_msrs(&mut self, mapper: &OffsetPageTable<'static>) {
        unsafe {
            // tsc_aux, star, lstar, cstar, fmask, kernel_gs_base.
            self.host_msr
                .set(x86::msr::IA32_TSC_AUX, rdmsr(x86::msr::IA32_TSC_AUX) as u64)
                .unwrap();
            self.host_msr
                .set(x86::msr::IA32_STAR, rdmsr(x86::msr::IA32_STAR) as u64)
                .unwrap();
            self.host_msr
                .set(x86::msr::IA32_LSTAR, rdmsr(x86::msr::IA32_LSTAR) as u64)
                .unwrap();
            self.host_msr
                .set(x86::msr::IA32_CSTAR, rdmsr(x86::msr::IA32_CSTAR) as u64)
                .unwrap();
            self.host_msr
                .set(x86::msr::IA32_FMASK, rdmsr(x86::msr::IA32_FMASK) as u64)
                .unwrap();
            self.host_msr
                .set(
                    x86::msr::IA32_KERNEL_GSBASE,
                    rdmsr(x86::msr::IA32_KERNEL_GSBASE) as u64,
                )
                .unwrap();

            self.guest_msr.set(x86::msr::IA32_TSC_AUX, 0).unwrap();
            self.guest_msr.set(x86::msr::IA32_STAR, 0).unwrap();
            self.guest_msr.set(x86::msr::IA32_LSTAR, 0).unwrap();
            self.guest_msr.set(x86::msr::IA32_CSTAR, 0).unwrap();
            self.guest_msr.set(x86::msr::IA32_FMASK, 0).unwrap();
            self.guest_msr.set(x86::msr::IA32_KERNEL_GSBASE, 0).unwrap();

            vmwrite(
                vmcs::control::VMEXIT_MSR_LOAD_ADDR_FULL,
                self.host_msr.phys(&mapper).as_u64(),
            )
            .unwrap();
            vmwrite(
                vmcs::control::VMEXIT_MSR_STORE_ADDR_FULL,
                self.guest_msr.phys(&mapper).as_u64(),
            )
            .unwrap();
            vmwrite(
                vmcs::control::VMENTRY_MSR_LOAD_ADDR_FULL,
                self.guest_msr.phys(&mapper).as_u64(),
            )
            .unwrap();
        }
    }

    pub fn update_msrs(&mut self) {
        let indices_to_update: alloc::vec::Vec<u32> = self
            .host_msr
            .saved_ents()
            .iter()
            .map(|entry| entry.index)
            .collect();

        for index in indices_to_update {
            let value = unsafe { rdmsr(index) };
            self.host_msr.set_by_index(index, value).unwrap();
        }

        unsafe {
            vmwrite(
                vmcs::control::VMEXIT_MSR_LOAD_COUNT,
                self.host_msr.saved_ents().len() as u64,
            )
            .unwrap();
            vmwrite(
                vmcs::control::VMEXIT_MSR_STORE_COUNT,
                self.guest_msr.saved_ents().len() as u64,
            )
            .unwrap();
            vmwrite(
                vmcs::control::VMENTRY_MSR_LOAD_COUNT,
                self.guest_msr.saved_ents().len() as u64,
            )
            .unwrap();
        }
    }

    pub fn setup_exec_ctrls(&mut self) -> Result<(), VmFail> {
        info!("Setting up pin based execution controls");
        let basic_msr = unsafe { rdmsr(x86::msr::IA32_VMX_BASIC) };
        let mut pin_exec_ctrl = PinBasedVmExecutionControls::read();

        let reserved_bits = if basic_msr & (1 << 55) != 0 {
            unsafe { rdmsr(x86::msr::IA32_VMX_TRUE_PINBASED_CTLS) }
        } else {
            unsafe { rdmsr(x86::msr::IA32_VMX_PINBASED_CTLS) }
        };

        pin_exec_ctrl.0 |= (reserved_bits & 0xFFFFFFFF) as u32;
        pin_exec_ctrl.0 &= (reserved_bits >> 32) as u32;

        pin_exec_ctrl.write();

        info!("Setting up primary execution controls");

        let mut primary_exec_ctrl = PrimaryProcessorBasedVmExecutionControls::read();

        let reserved_bits = if basic_msr & (1 << 55) != 0 {
            unsafe { rdmsr(x86::msr::IA32_VMX_TRUE_PROCBASED_CTLS) }
        } else {
            unsafe { rdmsr(x86::msr::IA32_VMX_PROCBASED_CTLS) }
        };

        primary_exec_ctrl.0 |= (reserved_bits & 0xFFFFFFFF) as u32;
        primary_exec_ctrl.0 &= (reserved_bits >> 32) as u32;
        primary_exec_ctrl.set_hlt(true);
        primary_exec_ctrl.set_activate_secondary_controls(true);
        primary_exec_ctrl.set_use_tpr_shadow(true);
        primary_exec_ctrl.set_use_msr_bitmap(false);

        primary_exec_ctrl.write();

        info!("Setting up secondary execution controls");

        let mut secondary_exec_ctrl = SecondaryProcessorBasedVmExecutionControls::read();

        let reserved_bits = if basic_msr & (1 << 55) != 0 {
            unsafe { rdmsr(x86::msr::IA32_VMX_PROCBASED_CTLS2) }
        } else {
            0
        };

        secondary_exec_ctrl.0 |= (reserved_bits & 0xFFFFFFFF) as u32;
        secondary_exec_ctrl.0 &= (reserved_bits >> 32) as u32;
        secondary_exec_ctrl.set_ept(true);
        secondary_exec_ctrl.set_unrestricted_guest(true);

        secondary_exec_ctrl.write();

        unsafe {
            vmwrite(vmcs::control::CR0_GUEST_HOST_MASK, u64::MAX).unwrap();
            vmwrite(vmcs::control::CR4_GUEST_HOST_MASK, u64::MAX).unwrap();
        }

        Ok(())
    }

    pub fn setup_entry_ctrls(&mut self) -> Result<(), VmFail> {
        info!("Setting up entry controls");

        let basic_msr = unsafe { rdmsr(x86::msr::IA32_VMX_BASIC) };

        let mut entry_ctrl = EntryControls::read();

        let reserved_bits = if basic_msr & (1 << 55) != 0 {
            unsafe { rdmsr(x86::msr::IA32_VMX_TRUE_ENTRY_CTLS) }
        } else {
            unsafe { rdmsr(x86::msr::IA32_VMX_ENTRY_CTLS) }
        };

        entry_ctrl.0 |= (reserved_bits & 0xFFFFFFFF) as u32;
        entry_ctrl.0 &= (reserved_bits >> 32) as u32;
        entry_ctrl.set_ia32e_mode_guest(false);
        entry_ctrl.set_load_ia32_efer(true);
        entry_ctrl.set_load_ia32_pat(true);

        entry_ctrl.write();

        Ok(())
    }

    pub fn setup_exit_ctrls(&mut self) -> Result<(), VmFail> {
        info!("Setting up exit controls");

        let basic_msr = unsafe { rdmsr(x86::msr::IA32_VMX_BASIC) };

        let mut exit_ctrl = PrimaryExitControls::read();

        let reserved_bits = if basic_msr & (1 << 55) != 0 {
            unsafe { rdmsr(x86::msr::IA32_VMX_TRUE_EXIT_CTLS) }
        } else {
            unsafe { rdmsr(x86::msr::IA32_VMX_EXIT_CTLS) }
        };

        exit_ctrl.0 |= (reserved_bits & 0xFFFFFFFF) as u32;
        exit_ctrl.0 &= (reserved_bits >> 32) as u32;
        exit_ctrl.set_host_addr_space_size(true);
        exit_ctrl.set_load_ia32_efer(true);
        exit_ctrl.set_save_ia32_efer(true);
        exit_ctrl.set_load_ia32_pat(true);
        exit_ctrl.set_save_ia32_pat(true);

        exit_ctrl.write();

        Ok(())
    }

    pub fn setup_host_state(&mut self) -> Result<(), VmFail> {
        info!("Setting up host state");
        unsafe {
            vmwrite(vmcs::host::CR0, cr0().bits() as u64)?;
            vmwrite(vmcs::host::CR3, cr3())?;
            vmwrite(vmcs::host::CR4, cr4().bits() as u64)?;

            vmwrite(vmcs::host::RIP, crate::vmm::asm::asm_vmexit_handler as u64)?;
            vmwrite(
                vmcs::host::RSP,
                VirtAddr::from_ptr(&raw mut TEMP_STACK).as_u64() + TEMP_STACK_SIZE as u64,
            )?;

            vmwrite(
                vmcs::host::ES_SELECTOR,
                x86::segmentation::es().bits() as u64,
            )?;
            vmwrite(
                vmcs::host::CS_SELECTOR,
                x86::segmentation::cs().bits() as u64,
            )?;
            vmwrite(
                vmcs::host::SS_SELECTOR,
                x86::segmentation::ss().bits() as u64,
            )?;
            vmwrite(
                vmcs::host::DS_SELECTOR,
                x86::segmentation::ds().bits() as u64,
            )?;
            vmwrite(
                vmcs::host::FS_SELECTOR,
                x86::segmentation::fs().bits() as u64,
            )?;
            vmwrite(
                vmcs::host::GS_SELECTOR,
                x86::segmentation::gs().bits() as u64,
            )?;
            vmwrite(vmcs::host::FS_BASE, rdmsr(IA32_FS_BASE))?;
            vmwrite(vmcs::host::GS_BASE, rdmsr(IA32_FS_BASE))?;

            let tr = x86::task::tr();
            let mut gdtp = DescriptorTablePointer::<u64>::default();
            let mut idtp = DescriptorTablePointer::<u64>::default();
            dtables::sgdt(&mut gdtp);
            dtables::sidt(&mut idtp);
            vmwrite(vmcs::host::GDTR_BASE, gdtp.base as u64)?;
            vmwrite(vmcs::host::IDTR_BASE, idtp.base as u64)?;
            vmwrite(vmcs::host::TR_SELECTOR, tr.bits() as u64)?;
            vmwrite(vmcs::host::TR_BASE, 0)?;

            vmwrite(vmcs::host::IA32_EFER_FULL, rdmsr(IA32_EFER))?;
        }
        Ok(())
    }

    pub fn setup_guest_state(&mut self) -> Result<(), VmFail> {
        info!("Setting up guest state");

        unsafe {
            let cr0 = (Cr0::empty() | Cr0::CR0_PROTECTED_MODE | Cr0::CR0_NUMERIC_ERROR)
                & !Cr0::CR0_ENABLE_PAGING;
            vmwrite(vmcs::guest::CR0, cr0.bits() as u64)?;
            vmwrite(vmcs::guest::CR3, cr3())?;
            vmwrite(
                vmcs::guest::CR4,
                vmread(vmcs::guest::CR4)?
                    | 1 << 5
                    | 1 << 7
                    | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits(),
            )?;

            vmwrite(vmcs::guest::CS_BASE, 0)?;
            vmwrite(vmcs::guest::SS_BASE, 0)?;
            vmwrite(vmcs::guest::DS_BASE, 0)?;
            vmwrite(vmcs::guest::ES_BASE, 0)?;
            vmwrite(vmcs::guest::TR_BASE, 0)?;
            vmwrite(vmcs::guest::GDTR_BASE, 0)?;
            vmwrite(vmcs::guest::IDTR_BASE, 0)?;
            vmwrite(vmcs::guest::LDTR_BASE, 0xDEAD00)?;

            vmwrite(vmcs::guest::CS_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::SS_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::DS_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::ES_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::FS_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::GS_LIMIT, u32::MAX as u64)?;
            vmwrite(vmcs::guest::TR_LIMIT, 0)?;
            vmwrite(vmcs::guest::GDTR_LIMIT, 0)?;
            vmwrite(vmcs::guest::IDTR_LIMIT, 0)?;
            vmwrite(vmcs::guest::LDTR_LIMIT, 0)?;

            let cs_right = {
                let mut rights = SegmentRights::default();
                rights.set_rw(true);
                rights.set_dc(false);
                rights.set_executable(true);
                rights.set_desc_type_raw(DescriptorType::Code as u8);
                rights.set_dpl(0);
                rights.set_granularity_raw(Granularity::KByte as u8);
                rights.set_long(false);
                rights.set_db(true);

                rights
            };

            let ds_right = {
                let mut rights = SegmentRights::default();
                rights.set_rw(true);
                rights.set_dc(false);
                rights.set_executable(false);
                rights.set_desc_type_raw(DescriptorType::Code as u8);
                rights.set_dpl(0);
                rights.set_granularity_raw(Granularity::KByte as u8);
                rights.set_long(false);
                rights.set_db(true);

                rights
            };

            let tr_right = {
                let mut rights = SegmentRights::default();
                rights.set_rw(true);
                rights.set_dc(false);
                rights.set_executable(true);
                rights.set_desc_type_raw(DescriptorType::System as u8);
                rights.set_dpl(0);
                rights.set_granularity_raw(Granularity::Byte as u8);
                rights.set_long(false);
                rights.set_db(false);

                rights
            };

            let ldtr_right = {
                let mut rights = SegmentRights::default();
                rights.set_accessed(false);
                rights.set_rw(true);
                rights.set_dc(false);
                rights.set_executable(false);
                rights.set_desc_type_raw(DescriptorType::System as u8);
                rights.set_dpl(0);
                rights.set_granularity_raw(Granularity::Byte as u8);
                rights.set_long(false);
                rights.set_db(false);

                rights
            };

            vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, cs_right.0 as u64)?;
            vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, ds_right.0 as u64)?;
            vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, ds_right.0 as u64)?;
            vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, ds_right.0 as u64)?;
            vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, ds_right.0 as u64)?;
            vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, ds_right.0 as u64)?;
            vmwrite(vmcs::guest::TR_ACCESS_RIGHTS, tr_right.0 as u64)?;
            vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, ldtr_right.0 as u64)?;

            vmwrite(vmcs::guest::CS_SELECTOR, 0)?;
            vmwrite(vmcs::guest::SS_SELECTOR, 0)?;
            vmwrite(vmcs::guest::DS_SELECTOR, 0)?;
            vmwrite(vmcs::guest::ES_SELECTOR, 0)?;
            vmwrite(vmcs::guest::FS_SELECTOR, 0)?;
            vmwrite(vmcs::guest::GS_SELECTOR, 0)?;
            vmwrite(vmcs::guest::TR_SELECTOR, 0)?;
            vmwrite(vmcs::guest::LDTR_SELECTOR, 0)?;
            vmwrite(vmcs::guest::FS_BASE, 0)?;
            vmwrite(vmcs::guest::GS_BASE, 0)?;

            vmwrite(vmcs::guest::IA32_EFER_FULL, 0)?;
            vmwrite(vmcs::guest::IA32_EFER_HIGH, 0)?;
            vmwrite(vmcs::guest::RFLAGS, 0x2)?;
            vmwrite(vmcs::guest::LINK_PTR_FULL, u64::MAX)?;

            vmwrite(vmcs::guest::RIP, linux::LAYOUT_KERNEL_BASE as u64)?;
            self.guest_registers.rsi = linux::LAYOUT_BOOTPARAM as u64;

            let cr0 = vmread(vmcs::guest::CR0)?;
            let cr4 = vmread(vmcs::guest::CR4)?;
            vmwrite(vmcs::control::CR0_READ_SHADOW, cr0)?;
            vmwrite(vmcs::control::CR4_READ_SHADOW, cr4)?;
        }

        Ok(())
    }

    pub fn reset_vmcs(&mut self) -> Result<(), VmFail> {
        info!("Resetting VMCS");
        self.vmcs.reset()
    }

    pub fn vm_loop(&mut self) -> ! {
        info!("Entering VM loop");

        loop {
            if let Err(err) = self.vmentry() {
                info!("VMEntry failed: {}", err.as_str());
            }

            self.vmexit_handler();
        }
    }

    fn vmentry(&mut self) -> Result<(), InstructionError> {
        let success = {
            let result: u16;

            unsafe {
                result = crate::vmm::asm::asm_vm_entry(self as *mut _);
            };
            result == 0
        };

        if !self.launch_done && success {
            self.launch_done = true;
        }

        if !success {
            let error = InstructionError::read();
            if error.0 != 0 {
                return Err(error);
            }
        }

        Ok(())
    }

    #[no_mangle]
    unsafe extern "C" fn set_host_stack(rsp: u64) {
        vmwrite(vmcs::host::RSP, rsp).unwrap();
    }

    fn step_next_inst(&mut self) -> Result<(), VmFail> {
        unsafe {
            let rip = vmread(vmcs::guest::RIP)?;
            vmwrite(
                vmcs::guest::RIP,
                rip + vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN)?,
            )
        }
    }

    fn vmexit_handler(&mut self) {
        let info = VmxExitInfo::read();

        if info.entry_failure() {
            let reason = info.0 & 0xFF;
            match reason {
                33 => {
                    info!("    Reason: VM-entry failure due to invalid guest state");
                }
                34 => {
                    info!("    Reason: VM-entry failure due to MSR loading");
                }
                41 => {
                    info!("    Reason: VM-entry failure due to machine-check event");
                }
                _ => {}
            }
        } else {
            match info.get_reason() {
                VmxExitReason::HLT => {
                    info!("HLT instruction executed");
                }
                VmxExitReason::CPUID => {
                    cpuid::handle_cpuid_exit(self);
                    self.step_next_inst().unwrap();
                }
                VmxExitReason::RDMSR => {
                    msr::ShadowMsr::handle_rdmsr_vmexit(self);
                    self.step_next_inst().unwrap();
                }
                VmxExitReason::WRMSR => {
                    msr::ShadowMsr::handle_wrmsr_vmexit(self);
                    self.step_next_inst().unwrap();
                }
                VmxExitReason::CONTROL_REGISTER_ACCESSES => {
                    let qual = unsafe { vmread(vmcs::ro::EXIT_QUALIFICATION).unwrap() };
                    let qual = QualCr(qual);
                    cr::handle_cr_access(self, &qual);
                    self.step_next_inst().unwrap();
                }
                _ => {
                    panic!("VMExit reason: {:?}", info.get_reason());
                }
            }
        }
    }
}
