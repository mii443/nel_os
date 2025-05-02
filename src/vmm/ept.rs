use core::sync::atomic::Ordering;

use bitfield::bitfield;
use x86_64::{
    structures::paging::{FrameAllocator, PhysFrame, Size4KiB},
    PhysAddr,
};

use crate::{info, memory};

pub struct EPT {
    pub root_table: PhysFrame,
}

impl EPT {
    pub fn new(allocator: &mut impl FrameAllocator<Size4KiB>) -> Self {
        let root_frame = allocator.allocate_frame().unwrap();

        _ = Self::init_table(&root_frame);

        Self {
            root_table: root_frame,
        }
    }

    fn frame_to_table_ptr(frame: &PhysFrame) -> &'static mut [EntryBase; 512] {
        let phys_addr_offset = memory::PHYSICAL_MEMORY_OFFSET.load(Ordering::Relaxed);
        let table_ptr = frame.start_address().as_u64() + phys_addr_offset;

        unsafe { &mut *(table_ptr as *mut [EntryBase; 512]) }
    }

    fn init_table(frame: &PhysFrame) -> &'static mut [EntryBase; 512] {
        let phys_addr_offset = memory::PHYSICAL_MEMORY_OFFSET.load(Ordering::Relaxed);
        let table_ptr = frame.start_address().as_u64() + phys_addr_offset;

        for entry in unsafe { &mut *(table_ptr as *mut [EntryBase; 512]) } {
            entry.set_read(false);
            entry.set_write(false);
            entry.set_exec_super(false);
            entry.set_map_memory(false);
            entry.set_typ(0);
        }

        unsafe { &mut *(table_ptr as *mut [EntryBase; 512]) }
    }

    pub fn map_2m(
        &mut self,
        gpa: u64,
        hpa: u64,
        allocator: &mut impl FrameAllocator<Size4KiB>,
    ) -> Result<(), &'static str> {
        let lv4_index = (gpa >> 39) & 0x1FF;
        let lv3_index = (gpa >> 30) & 0x1FF;
        let lv2_index = (gpa >> 21) & 0x1FF;

        let lv4_table = Self::frame_to_table_ptr(&self.root_table);
        let lv4_entry = &mut lv4_table[lv4_index as usize];

        let lv3_table = if !lv4_entry.present() {
            let frame = allocator
                .allocate_frame()
                .ok_or("Failed to allocate frame")?;
            let table_ptr = Self::init_table(&frame);
            lv4_entry.set_phys(frame.start_address().as_u64() >> 12);
            lv4_entry.set_map_memory(false);
            lv4_entry.set_typ(0);
            lv4_entry.set_read(true);
            lv4_entry.set_write(true);
            lv4_entry.set_exec_super(true);
            table_ptr
        } else {
            let frame =
                PhysFrame::from_start_address(PhysAddr::new(lv4_entry.phys() << 12)).unwrap();
            Self::frame_to_table_ptr(&frame)
        };

        let lv3_entry = &mut lv3_table[lv3_index as usize];

        let lv2_table = if !lv3_entry.present() {
            let frame = allocator
                .allocate_frame()
                .ok_or("Failed to allocate frame")?;
            let table_ptr = Self::init_table(&frame);
            lv3_entry.set_phys(frame.start_address().as_u64() >> 12);
            lv3_entry.set_map_memory(false);
            lv3_entry.set_typ(0);
            lv3_entry.set_read(true);
            lv3_entry.set_write(true);
            lv3_entry.set_exec_super(true);
            table_ptr
        } else {
            let frame =
                PhysFrame::from_start_address(PhysAddr::new(lv3_entry.phys() << 12)).unwrap();
            Self::frame_to_table_ptr(&frame)
        };

        let lv2_entry = &mut lv2_table[lv2_index as usize];
        lv2_entry.set_phys(hpa >> 12);
        lv2_entry.set_map_memory(true);
        lv2_entry.set_typ(0);
        lv2_entry.set_read(true);
        lv2_entry.set_write(true);
        lv2_entry.set_exec_super(true);

        Ok(())
    }

    pub fn get_phys_addr(&self, gpa: u64) -> Option<u64> {
        let lv4_index = (gpa >> 39) & 0x1FF;
        let lv3_index = (gpa >> 30) & 0x1FF;
        let lv2_index = (gpa >> 21) & 0x1FF;
        let page_offset = gpa & 0x1FFFFF;

        let lv4_table = Self::frame_to_table_ptr(&self.root_table);
        let lv4_entry = &lv4_table[lv4_index as usize];

        let frame = PhysFrame::from_start_address(PhysAddr::new(lv4_entry.phys() << 12)).unwrap();
        let lv3_table = Self::frame_to_table_ptr(&frame);
        let lv3_entry = &lv3_table[lv3_index as usize];

        let frame = PhysFrame::from_start_address(PhysAddr::new(lv3_entry.phys() << 12)).unwrap();
        let lv2_table = Self::frame_to_table_ptr(&frame);
        let lv2_entry = &lv2_table[lv2_index as usize];

        if !lv2_entry.map_memory() {
            info!("EPT: No mapping found for GPA: {:#x}", gpa);
            info!("{:#x}", lv2_entry.address().as_u64());
            info!("{:#x}", lv2_entry as *const _ as u64);
            return None;
        }

        let phys_addr_base = lv2_entry.address().as_u64();
        Some(phys_addr_base | page_offset)
    }

    pub fn get(&mut self, gpa: u64) -> Result<u8, &'static str> {
        let hpa = self
            .get_phys_addr(gpa)
            .ok_or("Failed to get physical address")?;
        let phys_addr_offset = memory::PHYSICAL_MEMORY_OFFSET.load(Ordering::Relaxed);
        let hpa = hpa + phys_addr_offset;

        let guest_memory = unsafe { &*(hpa as *const u8) };
        Ok(*guest_memory)
    }

    pub fn set(&mut self, gpa: u64, value: u8) -> Result<(), &'static str> {
        let hpa = self
            .get_phys_addr(gpa)
            .ok_or("Failed to get physical address")?;
        let phys_addr_offset = memory::PHYSICAL_MEMORY_OFFSET.load(Ordering::Relaxed);
        let hpa = hpa + phys_addr_offset;

        let guest_memory = unsafe { &mut *(hpa as *mut u8) };
        *guest_memory = value;

        Ok(())
    }

    pub fn set_range(
        &mut self,
        gpa_start: u64,
        gpa_end: u64,
        value: u8,
    ) -> Result<(), &'static str> {
        let mut gpa = gpa_start;
        while gpa <= gpa_end {
            self.set(gpa, value)?;
            gpa += 1;
        }

        Ok(())
    }
}

bitfield! {
    pub struct EPTP(u64);
    impl Debug;

    pub typ, set_typ: 2, 0;
    pub level, set_level: 5, 3;
    pub dirty_accessed, set_dirty_accessed: 6;
    pub enforce_access_rights, set_enforce_access_rights: 7;
    pub phys, set_phys: 63, 12;
}

impl EPTP {
    pub fn new(lv4_table: &PhysFrame) -> Self {
        let mut eptp = EPTP(0);
        eptp.set_typ(6);
        eptp.set_level(3);
        eptp.set_dirty_accessed(true);
        eptp.set_enforce_access_rights(false);
        eptp.set_phys(lv4_table.start_address().as_u64() >> 12);

        eptp
    }

    pub fn get_lv4_table(&self) -> &mut [EntryBase; 512] {
        let phys_addr_offset = memory::PHYSICAL_MEMORY_OFFSET.load(Ordering::Relaxed);
        let table_ptr = (self.phys() << 12) + phys_addr_offset;

        unsafe { &mut *(table_ptr as *mut [EntryBase; 512]) }
    }
}

bitfield! {
    pub struct EntryBase(u64);
    impl Debug;

    pub read, set_read: 0;
    pub write, set_write: 1;
    pub exec_super, set_exec_super: 2;
    pub typ, set_typ: 5, 3;
    pub ignore_pat, set_ignore_pat: 6;
    pub map_memory, set_map_memory: 7;
    pub accessed, set_accessed: 8;
    pub dirty, set_dirty: 9;
    pub exec_user, set_exec_user: 10;
    pub phys, set_phys: 63, 12;
}

impl EntryBase {
    pub fn present(&self) -> bool {
        self.read() || self.write() || self.exec_super()
    }

    pub fn address(&self) -> PhysAddr {
        PhysAddr::new(self.phys() << 12)
    }
}

impl Default for EntryBase {
    fn default() -> Self {
        let mut entry = EntryBase(0);
        entry.set_read(true);
        entry.set_write(true);
        entry.set_exec_super(true);
        entry.set_typ(0);
        entry.set_ignore_pat(false);
        entry.set_map_memory(false);
        entry.set_accessed(false);
        entry.set_dirty(false);
        entry.set_exec_user(true);
        entry.set_phys(0);

        entry
    }
}
