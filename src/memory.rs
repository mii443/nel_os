use core::sync::atomic::AtomicU64;

use bootloader::bootinfo::{MemoryMap, MemoryRegionType};
use x86_64::{
    structures::paging::{FrameAllocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

pub static PHYSICAL_MEMORY_OFFSET: AtomicU64 = AtomicU64::new(0);

pub struct BootInfoFrameAllocator {
    memory_map: &'static MemoryMap,
    next: usize,
}

impl BootInfoFrameAllocator {
    pub unsafe fn init(memory_map: &'static MemoryMap) -> Self {
        Self {
            memory_map,
            next: 0,
        }
    }

    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> {
        let regions = self.memory_map.iter();
        let usable_regions = regions.filter(|r| r.region_type == MemoryRegionType::Usable);
        let addr_ranges = usable_regions.map(|r| r.range.start_addr()..r.range.end_addr());
        let frame_addresses = addr_ranges.flat_map(|r| r.step_by(4096));
        frame_addresses.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }

    pub fn allocate_2mib_aligned(&mut self) -> Option<PhysAddr> {
        self.allocate_2mib_frame()
            .map(|frame| frame.start_address())
    }

    pub fn allocate_2mib_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let mut frames = self.usable_frames().skip(self.next);

        let base_frame = frames.find(|frame| frame.start_address().as_u64() & 0x1F_FFFF == 0)?;

        let base_idx = self.next
            + frames
                .enumerate()
                .find(|(_, frame)| frame.start_address() == base_frame.start_address())
                .map(|(idx, _)| idx)
                .unwrap_or(0);

        let frame_count = 512;
        let frames_are_available = self
            .usable_frames()
            .skip(base_idx)
            .take(frame_count)
            .enumerate()
            .all(|(idx, frame)| {
                let expected_addr = base_frame.start_address().as_u64() + (idx as u64 * 4096);
                frame.start_address().as_u64() == expected_addr
            });

        if !frames_are_available {
            self.next = base_idx + 1;
            return self.allocate_2mib_frame();
        }

        self.next = base_idx + frame_count;

        Some(base_frame)
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}

unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;

    let (level_4_table_frame, _) = Cr3::read();

    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    unsafe { &mut *page_table_ptr }
}

pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    unsafe {
        let level_4_table = active_level_4_table(physical_memory_offset);
        OffsetPageTable::new(level_4_table, physical_memory_offset)
    }
}
