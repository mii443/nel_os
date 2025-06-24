use core::{
    arch::asm,
    arch::x86_64::{_xgetbv, _xsetbv},
    convert::TryInto,
    sync::atomic::{AtomicPtr, Ordering},
    u64, u8,
};

use x86::{
    bits64::vmx::{vmread, vmwrite},
    controlregs::{cr0, cr3, cr4, Cr0},
    dtables::{self, DescriptorTablePointer},
    irq,
    msr::{rdmsr, IA32_EFER, IA32_FS_BASE},
    vmx::{vmcs, VmFail},
};
use x86_64::{
    registers::control::Cr4Flags,
    structures::paging::{FrameAllocator, OffsetPageTable},
    VirtAddr,
};

use crate::{
    info,
    interrupts::vmm_subscriber,
    memory::BootInfoFrameAllocator,
    subscribe_with_context,
    vmm::{
        cpuid, cr, fpu,
        io::{self, InitPhase, Serial, PIC},
        msr,
        qual::{QualCr, QualIo},
        vmcs::{
            DescriptorType, EntryControls, EntryIntrInfo, Granularity, PrimaryExitControls,
            PrimaryProcessorBasedVmExecutionControls, SecondaryProcessorBasedVmExecutionControls,
            SegmentRights, VmxExitReason,
        },
    },
};

use super::{
    ept::{EPT, EPTP},
    fpu::XCR0,
    linux::{self, BootParams, E820Type},
    msr::ShadowMsr,
    register::GuestRegisters,
    vmcs::{InstructionError, PinBasedVmExecutionControls, Vmcs},
    vmxon::Vmxon,
};

const SIZE_2MIB: u64 = 2 * 1024 * 1024;

static EPT_FRAME_ALLOCATOR: AtomicPtr<BootInfoFrameAllocator> = AtomicPtr::new(core::ptr::null_mut());

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
    pub xcr0: XCR0,
    pub host_xcr0: u64,
    pub serial: Serial,
    pub io_bitmap_a: x86_64::structures::paging::PhysFrame,
    pub io_bitmap_b: x86_64::structures::paging::PhysFrame,
    pub pic: PIC,
    pub pending_irq: u16,
}

const TEMP_STACK_SIZE: usize = 4096;
static mut TEMP_STACK: [u8; TEMP_STACK_SIZE + 0x10] = [0; TEMP_STACK_SIZE + 0x10];

impl VCpu {
    fn translate_guest_address(&mut self, vaddr: u64) -> Result<u64, &'static str> {
        // Read guest CR3
        let cr3 = unsafe { vmread(vmcs::guest::CR3).map_err(|_| "Failed to read guest CR3")? };
        let pml4_base = cr3 & !0xFFF; // Clear lower 12 bits to get page table base

        // Check if guest is in long mode (64-bit)
        let efer = unsafe { vmread(vmcs::guest::IA32_EFER_FULL).unwrap_or(0) };
        let is_long_mode = (efer & (1 << 8)) != 0; // LME bit

        if !is_long_mode {
            return Ok(vaddr & 0xFFFFFFFF);
        }

        // Extract page table indices for 4-level paging
        let pml4_idx = ((vaddr >> 39) & 0x1FF) as u64;
        let pdpt_idx = ((vaddr >> 30) & 0x1FF) as u64;
        let pd_idx = ((vaddr >> 21) & 0x1FF) as u64;
        let pt_idx = ((vaddr >> 12) & 0x1FF) as u64;
        let page_offset = (vaddr & 0xFFF) as u64;

        // Walk PML4
        let pml4_entry_addr = pml4_base + (pml4_idx * 8);
        let pml4_entry = self.read_guest_phys_u64(pml4_entry_addr)?;
        if (pml4_entry & 1) == 0 {
            return Err("PML4 entry not present");
        }
        let pdpt_base = pml4_entry & 0x000FFFFFFFFFF000;

        // Walk PDPT
        let pdpt_entry_addr = pdpt_base + (pdpt_idx * 8);
        let pdpt_entry = self.read_guest_phys_u64(pdpt_entry_addr)?;
        if (pdpt_entry & 1) == 0 {
            return Err("PDPT entry not present");
        }
        // Check for 1GB page
        if (pdpt_entry & (1 << 7)) != 0 {
            let page_base = pdpt_entry & 0x000FFFFFC0000000;
            return Ok(page_base | (vaddr & 0x3FFFFFFF));
        }
        let pd_base = pdpt_entry & 0x000FFFFFFFFFF000;

        // Walk PD
        let pd_entry_addr = pd_base + (pd_idx * 8);
        let pd_entry = self.read_guest_phys_u64(pd_entry_addr)?;
        if (pd_entry & 1) == 0 {
            return Err("PD entry not present");
        }
        // Check for 2MB page
        if (pd_entry & (1 << 7)) != 0 {
            let page_base = pd_entry & 0x000FFFFFFFE00000;
            return Ok(page_base | (vaddr & 0x1FFFFF));
        }
        let pt_base = pd_entry & 0x000FFFFFFFFFF000;

        // Walk PT
        let pt_entry_addr = pt_base + (pt_idx * 8);
        let pt_entry = self.read_guest_phys_u64(pt_entry_addr)?;
        if (pt_entry & 1) == 0 {
            return Err("PT entry not present");
        }
        let page_base = pt_entry & 0x000FFFFFFFFFF000;

        Ok(page_base | page_offset)
    }

    fn read_guest_phys_u64(&mut self, gpa: u64) -> Result<u64, &'static str> {
        let mut result_bytes = [0u8; 8];

        for i in 0..8 {
            match self.ept.get(gpa + i) {
                Ok(byte) => result_bytes[i as usize] = byte,
                Err(_) => return Err("Failed to read from EPT"),
            }
        }

        Ok(u64::from_le_bytes(result_bytes))
    }

    pub fn new(phys_mem_offset: u64, frame_allocator: &mut BootInfoFrameAllocator) -> Self {
        let mut vmxon = Vmxon::new(frame_allocator);
        vmxon.init(phys_mem_offset);
        let vmcs = Vmcs::new(frame_allocator);
        let ept = EPT::new(frame_allocator);
        let eptp = EPTP::new(&ept.root_table);

        // Allocate I/O bitmaps (4KB each)
        let io_bitmap_a = frame_allocator.allocate_frame().unwrap();
        let io_bitmap_b = frame_allocator.allocate_frame().unwrap();

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
            xcr0: XCR0(3),
            host_xcr0: 0,
            serial: Serial::default(),
            io_bitmap_a,
            io_bitmap_b,
            pic: PIC::new(),
            pending_irq: 0,
        }
    }

    pub fn activate(
        &mut self,
        frame_allocator: &mut BootInfoFrameAllocator,
        mapper: &OffsetPageTable<'static>,
    ) {
        EPT_FRAME_ALLOCATOR.store(frame_allocator as *mut _, Ordering::Release);
        
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
        self.setup_io_bitmaps();
        let _ = self.setup_guest_memory(frame_allocator);
        self.register_msrs(&mapper);
    }

    pub fn load_kernel(&mut self, kernel: &[u8], guest_mem_size: u64) {
        info!("Loading kernel into guest memory");
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
        bp.hdr.ramdisk_image = linux::LAYOUT_INITRD as u32;
        bp.hdr.ramdisk_size = linux::INITRD.len() as u32;

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
        
        let cmdline_bytes = b"console=ttyS0 earlyprintk=serial nokaslr\0";
        self.load_image(cmdline_bytes, cmdline_start as usize);

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

        info!(
            "Loading initrd at {:#x}, size: {} bytes",
            linux::LAYOUT_INITRD,
            linux::INITRD.len()
        );
        self.load_image(linux::INITRD, linux::LAYOUT_INITRD as usize);

        info!("Kernel loaded into guest memory");
    }

    pub fn load_image(&mut self, image: &[u8], addr: usize) {
        info!("Loading image at {:#x}, size: {} bytes", addr, image.len());
        
        let start_page = addr & !0xFFF;
        let end_page = ((addr + image.len() - 1) & !0xFFF) + 0x1000;
        
        unsafe {
            let frame_allocator_ptr = EPT_FRAME_ALLOCATOR.load(Ordering::Acquire);
            if !frame_allocator_ptr.is_null() {
                let frame_allocator = &mut *(frame_allocator_ptr as *mut BootInfoFrameAllocator);
                
                let mut current_page = start_page;
                while current_page < end_page {
                    if self.ept.get_phys_addr(current_page as u64).is_none() {
                        if let Some(frame) = frame_allocator.allocate_frame() {
                            let hpa = frame.start_address().as_u64();
                            self.ept.map_4k(current_page as u64, hpa, frame_allocator).unwrap();
                        } else {
                            panic!("Failed to allocate frame for image at {:#x}", current_page);
                        }
                    }
                    current_page += 0x1000;
                }
            }
        }
        
        for (i, &byte) in image.iter().enumerate() {
            let gpa = addr + i;
            self.ept.set(gpa as u64, byte).unwrap();
        }
    }

    pub fn setup_guest_memory(&mut self, frame_allocator: &mut BootInfoFrameAllocator) -> u64 {
        let guest_memory_size = 2 * 1024 * 1024 * 1024;

        info!("Setting up guest memory with on-demand allocation (reported size: {}MB)", 
              guest_memory_size / (1024 * 1024));

        self.load_kernel(linux::BZIMAGE, guest_memory_size);

        let eptp = EPTP::new(&self.ept.root_table);
        unsafe { vmwrite(vmcs::control::EPTP_FULL, eptp.0).unwrap() };

        guest_memory_size
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
            self.host_msr
                .set(x86::msr::MSR_C5_PMON_BOX_CTRL, 0)
                .unwrap();

            self.guest_msr.set(x86::msr::IA32_TSC_AUX, 0).unwrap();
            self.guest_msr.set(x86::msr::IA32_STAR, 0).unwrap();
            self.guest_msr.set(x86::msr::IA32_LSTAR, 0).unwrap();
            self.guest_msr.set(x86::msr::IA32_CSTAR, 0).unwrap();
            self.guest_msr.set(x86::msr::IA32_FMASK, 0).unwrap();
            self.guest_msr.set(x86::msr::IA32_KERNEL_GSBASE, 0).unwrap();
            self.guest_msr
                .set(x86::msr::MSR_C5_PMON_BOX_CTRL, 0)
                .unwrap();
            self.guest_msr.set(0x1b, 0).unwrap();

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
        pin_exec_ctrl.set_external_interrupt_exiting(true);

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
        primary_exec_ctrl.set_use_tpr_shadow(false);
        primary_exec_ctrl.set_use_msr_bitmap(false);
        primary_exec_ctrl.set_unconditional_io(false);
        primary_exec_ctrl.set_use_io_bitmap(true);

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
        secondary_exec_ctrl.set_virtualize_apic_accesses(false);

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

        unsafe {
            vmwrite(
                vmcs::control::EXCEPTION_BITMAP,
                1u64 << irq::INVALID_OPCODE_VECTOR,
            )
            .unwrap();
        };

        Ok(())
    }

    pub fn setup_io_bitmaps(&mut self) {
        info!("Setting up I/O bitmaps");

        let bitmap_a_vaddr = self.io_bitmap_a.start_address().as_u64() + self.phys_mem_offset;
        let bitmap_b_vaddr = self.io_bitmap_b.start_address().as_u64() + self.phys_mem_offset;

        unsafe {
            core::ptr::write_bytes(bitmap_a_vaddr as *mut u8, u8::MAX, 4096);
            core::ptr::write_bytes(bitmap_b_vaddr as *mut u8, u8::MAX, 4096);
        }

        let bitmap_a = unsafe { core::slice::from_raw_parts_mut(bitmap_a_vaddr as *mut u8, 4096) };
        let bitmap_b = unsafe { core::slice::from_raw_parts_mut(bitmap_b_vaddr as *mut u8, 4096) };

        self.set_io_ports(bitmap_a, bitmap_b, 0x02F8..=0x03FF);
        self.set_io_ports(bitmap_a, bitmap_b, 0x0040..=0x0047);

        unsafe {
            vmwrite(
                vmcs::control::IO_BITMAP_A_ADDR_FULL,
                self.io_bitmap_a.start_address().as_u64(),
            )
            .unwrap();
            vmwrite(
                vmcs::control::IO_BITMAP_B_ADDR_FULL,
                self.io_bitmap_b.start_address().as_u64(),
            )
            .unwrap();
        }

        info!("I/O bitmaps configured - PCI ports 0xC000-0xCFFF will trigger VM exits");
    }

    fn set_io_ports(
        &self,
        bitmap_a: &mut [u8],
        bitmap_b: &mut [u8],
        ports: core::ops::RangeInclusive<u16>,
    ) {
        for port in ports {
            if port <= 0x7FFF {
                let byte_index = port as usize / 8;
                let bit_index = port as usize % 8;
                bitmap_a[byte_index] &= !(1 << bit_index);
            } else {
                let adjusted_port = port - 0x8000;
                let byte_index = adjusted_port as usize / 8;
                let bit_index = adjusted_port as usize % 8;
                bitmap_b[byte_index] &= !(1 << bit_index);
            }
        }
    }

    pub fn setup_host_state(&mut self) -> Result<(), VmFail> {
        info!("Setting up host state");
        unsafe {
            vmwrite(vmcs::host::CR0, cr0().bits() as u64)?;
            vmwrite(vmcs::host::CR3, cr3())?;
            vmwrite(
                vmcs::host::CR4,
                cr4().bits() as u64 | Cr4Flags::OSXSAVE.bits(),
            )?;

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
            let cr0 = (Cr0::empty()
                | Cr0::CR0_PROTECTED_MODE
                | Cr0::CR0_NUMERIC_ERROR
                | Cr0::CR0_EXTENSION_TYPE)
                & !Cr0::CR0_ENABLE_PAGING;
            vmwrite(vmcs::guest::CR0, cr0.bits() as u64)?;
            vmwrite(vmcs::guest::CR3, 0)?;
            vmwrite(
                vmcs::guest::CR4,
                vmread(vmcs::guest::CR4)?
                    | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits()
                        & !Cr4Flags::PHYSICAL_ADDRESS_EXTENSION.bits(),
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

        let vcpu: &mut VCpu = self;
        let vcpu_ptr = vcpu as *mut VCpu as *mut core::ffi::c_void;
        subscribe_with_context(vmm_subscriber, vcpu_ptr)
            .expect("Failed to subscribe to vmm_subscriber");

        loop {
            if let Err(err) = self.vmentry() {
                info!("VMEntry failed: {}", err.as_str());
            }

            self.vmexit_handler();
        }
    }

    fn load_guest_xcr0(&mut self) -> Result<(), VmFail> {
        let host_cr4 = unsafe { cr4() };
        if (host_cr4.bits() & Cr4Flags::OSXSAVE.bits() as usize) == 0 {
            return Ok(());
        }

        if self.host_xcr0 == 0 {
            self.host_xcr0 = unsafe { _xgetbv(0) };
        }

        let guest_cr4 = unsafe { vmread(vmcs::guest::CR4)? };

        if guest_cr4 & Cr4Flags::OSXSAVE.bits() != 0 && self.xcr0.0 != self.host_xcr0 {
            unsafe {
                _xsetbv(0, self.xcr0.0);
            }
        }

        Ok(())
    }

    fn load_host_xcr0(&mut self) -> Result<(), VmFail> {
        let host_cr4 = unsafe { cr4() };
        if (host_cr4.bits() & Cr4Flags::OSXSAVE.bits() as usize) == 0 {
            return Ok(());
        }

        let guest_cr4 = unsafe { vmread(vmcs::guest::CR4)? };

        if guest_cr4 & Cr4Flags::OSXSAVE.bits() != 0 {
            let current_xcr0 = unsafe { _xgetbv(0) };
            if current_xcr0 != self.host_xcr0 {
                self.xcr0 = XCR0(current_xcr0);
                unsafe {
                    _xsetbv(0, self.host_xcr0);
                }
            }
        }

        Ok(())
    }

    fn vmentry(&mut self) -> Result<(), InstructionError> {
        let success = {
            let result: u16;

            self.load_guest_xcr0().unwrap();
            unsafe {
                result = crate::vmm::asm::asm_vm_entry(self as *mut _);
            };
            self.load_host_xcr0().unwrap();
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

    fn inject_external_interrupt(&mut self) -> Result<bool, VmFail> {
        let pending = self.pending_irq;

        //info!("Injecting external interrupt: pending IRQs: {:#x}", pending);

        if pending == 0 {
            return Ok(false);
        }

        if self.pic.primary_phase != InitPhase::Initialized {
            return Ok(false);
        }

        let eflags = unsafe { vmread(vmcs::guest::RFLAGS) }?;
        if eflags >> 9 & 1 == 0 {
            return Ok(false);
        }

        // Check guest interruptibility state
        let interruptibility = unsafe { vmread(vmcs::guest::INTERRUPTIBILITY_STATE)? };
        if interruptibility & 0x3 != 0 {
            // STI-blocking (bit 0) or MOV SS-blocking (bit 1)
            return Ok(false);
        }

        let is_secondary_masked = (self.pic.primary_mask >> 2) & 1 != 0;

        for i in 0..16 {
            if is_secondary_masked && i >= 8 {
                break;
            }

            let irq_bit = 1 << i;
            if pending & irq_bit == 0 {
                continue;
            }

            let delta = if i < 8 { i } else { i - 8 };
            let is_masked = if i < 8 {
                (self.pic.primary_mask >> delta) & 1 != 0
            } else {
                let is_ieq_masked = (self.pic.secondary_mask >> delta) & 1 != 0;
                is_secondary_masked || is_ieq_masked
            };

            if is_masked {
                continue;
            }

            let mut interrupt_info = EntryIntrInfo(0);
            interrupt_info.set_vector(
                delta as u32
                    + if i < 8 {
                        self.pic.primary_base as u32
                    } else {
                        self.pic.secondary_base as u32
                    },
            );
            interrupt_info.set_type(0);
            interrupt_info.set_ec_available(false);
            interrupt_info.set_valid(true);
            unsafe {
                vmwrite(
                    vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
                    interrupt_info.0 as u64,
                )?;
            }

            self.pending_irq &= !irq_bit;
            return Ok(true);
        }

        Ok(false)
    }

    fn inject_exception(&mut self, vector: u32, error_code: Option<u32>) -> Result<(), VmFail> {
        let mut interrupt_info = EntryIntrInfo(0);
        interrupt_info.set_vector(vector);
        interrupt_info.set_type(3); // 3 = Hardware exception

        // Check if this exception requires an error code
        let has_error_code = match vector {
            8 | 10..=14 | 17 | 21 => true, // DF, TS, NP, SS, GP, PF, AC, CP
            _ => false,
        };

        interrupt_info.set_ec_available(has_error_code);
        interrupt_info.set_valid(true);

        unsafe {
            vmwrite(
                vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
                interrupt_info.0 as u64,
            )?;

            // If error code is required, write it
            if has_error_code {
                let ec = error_code.unwrap_or(0);
                vmwrite(vmcs::control::VMENTRY_EXCEPTION_ERR_CODE, ec as u64)?;
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

    fn handle_ept_violation(&mut self, gpa: u64) {
        if gpa >= 2 * 1024 * 1024 * 1024 {
            panic!("EPT Violation: Guest tried to access memory beyond 2GB at {:#x}", gpa);
        }

        unsafe {
            let frame_allocator_ptr = EPT_FRAME_ALLOCATOR.load(Ordering::Acquire);
            if frame_allocator_ptr.is_null() {
                panic!("EPT Violation: Frame allocator not initialized!");
            }
            
            let frame_allocator = &mut *(frame_allocator_ptr as *mut BootInfoFrameAllocator);
            
            match frame_allocator.allocate_frame() {
                Some(frame) => {
                    let hpa = frame.start_address().as_u64();
                    
                    if let Err(e) = self.ept.map_4k(gpa, hpa, frame_allocator) {
                        panic!("Failed to map page at GPA {:#x}: {}", gpa, e);
                    }
                }
                None => {
                    panic!("EPT Violation: Out of memory! Cannot allocate frame for GPA {:#x}", gpa);
                }
            }
        }
    }

    fn vmexit_handler(&mut self) {
        let exit_reason_raw = unsafe { vmread(vmcs::ro::EXIT_REASON).unwrap() as u32 };

        // Check if an interrupt was being delivered when VM-exit occurred
        use crate::vmm::vmcs::VmcsReadOnlyData32;
        let idt_vectoring_info = VmcsReadOnlyData32::IDT_VECTORING_INFORMATION_FIELD
            .read()
            .unwrap() as u64;
        if idt_vectoring_info & (1 << 31) != 0 {
            // Valid bit is set - an interrupt was being delivered
            // We need to reinject this interrupt
            unsafe {
                vmwrite(
                    vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD,
                    idt_vectoring_info,
                )
                .unwrap();
            }
        }

        if (exit_reason_raw & (1 << 31)) != 0 {
            // VM-entry failure
            let reason = exit_reason_raw & 0xFF;
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
            let basic_reason = (exit_reason_raw & 0xFFFF) as u16;
            let exit_reason: VmxExitReason = basic_reason.try_into().unwrap();
            match exit_reason {
                VmxExitReason::HLT => {
                    // Don't clear VMENTRY_INTERRUPTION_INFO_FIELD here - it may contain a reinjected interrupt

                    // Check if we have interrupts to inject
                    let injected = self.inject_external_interrupt().unwrap_or(false);

                    if !injected {
                        // No interrupt was injected, wait for one
                        unsafe {
                            asm!("sti");
                            asm!("nop");
                            asm!("cli");
                        }
                    }

                    unsafe {
                        vmwrite(vmcs::guest::ACTIVITY_STATE, 0).unwrap();
                        vmwrite(vmcs::guest::INTERRUPTIBILITY_STATE, 0).unwrap();
                    }
                    self.step_next_inst().unwrap();
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
                VmxExitReason::XSETBV => {
                    fpu::set_xcr(
                        self,
                        self.guest_registers.rcx as u32,
                        self.guest_registers.rax,
                    )
                    .unwrap();
                    self.step_next_inst().unwrap();
                }
                VmxExitReason::EXCEPTION => {
                    // Get exception information
                    let vmexit_intr_info =
                        unsafe { vmread(vmcs::ro::VMEXIT_INTERRUPTION_INFO).unwrap() };
                    let vector = (vmexit_intr_info & 0xFF) as u32;
                    let has_error_code = (vmexit_intr_info & (1 << 11)) != 0;

                    let error_code = if has_error_code {
                        Some(unsafe {
                            vmread(vmcs::ro::VMEXIT_INTERRUPTION_ERR_CODE).unwrap() as u32
                        })
                    } else {
                        None
                    };

                    // show guest RIP
                    let rip = unsafe { vmread(vmcs::guest::RIP).unwrap() };

                    // Read the instruction bytes at RIP
                    let mut instruction_bytes = [0u8; 16];
                    let mut valid_bytes = 0;

                    // Try to translate the virtual address to physical address
                    match self.translate_guest_address(rip) {
                        Ok(guest_phys_addr) => {
                            for i in 0..16 {
                                match self.ept.get(guest_phys_addr + i) {
                                    Ok(byte) => {
                                        instruction_bytes[i as usize] = byte;
                                        valid_bytes = i + 1;
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                        Err(e) => {
                            // Try reading directly as physical address if translation fails
                            if rip < 0x100000000 {
                                for i in 0..16 {
                                    match self.ept.get(rip + i) {
                                        Ok(byte) => {
                                            instruction_bytes[i as usize] = byte;
                                            valid_bytes = i + 1;
                                        }
                                        Err(_) => break,
                                    }
                                }
                            }
                        }
                    }

                    if valid_bytes > 0 {
                        match instruction_bytes[0] {
                            0x0F => {
                                if valid_bytes > 1 {
                                    match instruction_bytes[1] {
                                        0x01 => match instruction_bytes[2] {
                                            0xCA => {
                                                unsafe {
                                                    let rflags = vmread(vmcs::guest::RFLAGS).unwrap();
                                                    vmwrite(vmcs::guest::RFLAGS, rflags & !(1 << 18)).unwrap();
                                                }
                                                self.step_next_inst().unwrap();
                                            }
                                            0xCB => {
                                                unsafe {
                                                    let rflags = vmread(vmcs::guest::RFLAGS).unwrap();
                                                    vmwrite(vmcs::guest::RFLAGS, rflags | (1 << 18)).unwrap();
                                                }
                                                self.step_next_inst().unwrap();
                                            }
                                            _ => {
                                                self.inject_exception(vector, error_code).unwrap();
                                            }
                                        },
                                        _ => {
                                            self.inject_exception(vector, error_code).unwrap();
                                        }
                                    }
                                }
                            }
                            _ => {
                                self.inject_exception(vector, error_code).unwrap();
                            }
                        }
                    }
                }
                VmxExitReason::IO_INSTRUCTION => {
                    let qual = unsafe { vmread(vmcs::ro::EXIT_QUALIFICATION).unwrap() };
                    let qual_io = QualIo(qual);

                    io::handle_io(self, qual_io);
                    self.step_next_inst().unwrap();
                }
                VmxExitReason::EXTERNAL_INTERRUPT => {
                    // Clear any pending injection info first
                    unsafe {
                        vmwrite(vmcs::control::VMENTRY_INTERRUPTION_INFO_FIELD, 0).unwrap();
                    }

                    unsafe {
                        asm!("sti");
                        asm!("nop");
                        asm!("cli");
                    }
                    self.inject_external_interrupt().unwrap();
                }
                VmxExitReason::EPT_VIOLATION => {
                    let guest_address =
                        unsafe { vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL).unwrap() };
                    let exit_qualification =
                        unsafe { vmread(vmcs::ro::EXIT_QUALIFICATION).unwrap() };
                    let guest_rip = unsafe { vmread(vmcs::guest::RIP).unwrap() };

                    let read_access = (exit_qualification & 0x1) != 0;
                    let write_access = (exit_qualification & 0x2) != 0;
                    let execute_access = (exit_qualification & 0x4) != 0;
                    let gpa_valid = (exit_qualification & 0x80) != 0;
                    let translation_valid = (exit_qualification & 0x100) != 0;

                    let page_addr = guest_address & !0xFFF;
                    
                    self.handle_ept_violation(page_addr);
                }
                _ => {
                    panic!("VMExit reason: {:?}", exit_reason);
                }
            }
        }
    }
}
