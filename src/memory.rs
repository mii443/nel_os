use core::sync::atomic::{AtomicU64, Ordering};

use bootloader::bootinfo::{MemoryMap, MemoryRegionType};
use x86_64::{
    structures::paging::{FrameAllocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB},
    PhysAddr, VirtAddr,
};

pub static PHYSICAL_MEMORY_OFFSET: AtomicU64 = AtomicU64::new(0);

const SIZE_2MIB: u64 = 0x20_0000;
const ALIGN_2MIB_MASK: u64 = SIZE_2MIB - 1;

pub struct BootInfoFrameAllocator {
    memory_map: &'static MemoryMap,
    next: usize,
    aligned_regions: [(u64, u64); 32],
    aligned_count: usize,
}

impl BootInfoFrameAllocator {
    pub unsafe fn init(memory_map: &'static MemoryMap) -> Self {
        let mut allocator = Self {
            memory_map,
            next: 0,
            aligned_regions: [(0, 0); 32],
            aligned_count: 0,
        };

        allocator.cache_aligned_regions();

        allocator
    }

    fn cache_aligned_regions(&mut self) {
        self.aligned_count = 0;

        for region in self.memory_map.iter() {
            if region.region_type != MemoryRegionType::Usable {
                continue;
            }

            let start = region.range.start_addr();
            let end = region.range.end_addr();

            if end - start < SIZE_2MIB {
                continue;
            }

            let aligned_start = (start + ALIGN_2MIB_MASK) & !ALIGN_2MIB_MASK;

            if aligned_start + SIZE_2MIB <= end && self.aligned_count < self.aligned_regions.len() {
                self.aligned_regions[self.aligned_count] = (aligned_start, end);
                self.aligned_count += 1;
            }
        }
    }

    pub fn allocate_2mib_aligned(&mut self) -> Option<PhysAddr> {
        self.allocate_2mib_frame()
            .map(|frame| frame.start_address())
    }

    pub fn allocate_2mib_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        for i in 0..self.aligned_count {
            let (start, end) = self.aligned_regions[i];

            if start + SIZE_2MIB <= end {
                let frame = PhysFrame::containing_address(PhysAddr::new(start));

                self.aligned_regions[i].0 = start + SIZE_2MIB;

                return Some(frame);
            }
        }

        if self.aligned_count == 0 {
            self.cache_aligned_regions();
            return self.allocate_2mib_frame();
        }

        let mut frames = self.usable_frames().skip(self.next);

        let base_frame =
            frames.find(|frame| frame.start_address().as_u64() & ALIGN_2MIB_MASK == 0)?;

        let base_addr = base_frame.start_address().as_u64();

        let is_continuous = self
            .memory_map
            .iter()
            .filter(|r| r.region_type == MemoryRegionType::Usable)
            .any(|r| {
                let start = r.range.start_addr();
                let end = r.range.end_addr();
                base_addr >= start && base_addr + SIZE_2MIB <= end
            });

        if is_continuous {
            self.next += 512;
            return Some(base_frame);
        }

        None
    }

    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> {
        let regions = self.memory_map.iter();
        let usable_regions = regions.filter(|r| r.region_type == MemoryRegionType::Usable);
        let addr_ranges = usable_regions.map(|r| r.range.start_addr()..r.range.end_addr());
        let frame_addresses = addr_ranges.flat_map(|r| r.step_by(4096));
        frame_addresses.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
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

    &mut *page_table_ptr
}

pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    PHYSICAL_MEMORY_OFFSET.store(physical_memory_offset.as_u64(), Ordering::SeqCst);

    let level_4_table = active_level_4_table(physical_memory_offset);
    OffsetPageTable::new(level_4_table, physical_memory_offset)
}
