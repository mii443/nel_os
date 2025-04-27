use bitfield::bitfield;
use x86_64::{
    structures::paging::{OffsetPageTable, Translate},
    PhysAddr, VirtAddr,
};

pub enum Assert<const CHECK: bool> {}

pub trait IsTrue {}

impl IsTrue for Assert<true> {}

pub struct TableEntry<const LEVEL: u8> {
    pub entry: EntryBase,
}

impl<const LEVEL: u8> TableEntry<LEVEL> {
    pub fn new_map_table<const L: u8>(
        table: TableEntry<L>,
        mapper: OffsetPageTable<'static>,
    ) -> Self
    where
        Assert<{ LEVEL > L }>: IsTrue,
        Assert<{ L > 0 }>: IsTrue,
        Assert<{ LEVEL < 5 }>: IsTrue,
    {
        let mut entry = EntryBase::default();
        entry.set_map_memory(false);
        entry.set_typ(0);
        entry.set_phys(
            (mapper
                .translate_addr(VirtAddr::from_ptr(&table))
                .unwrap()
                .as_u64())
                >> 12,
        );

        Self { entry }
    }

    pub fn new_map_page<const L: u8>(phys: u64, mapper: OffsetPageTable<'static>) -> Self
    where
        Assert<{ L < 4 }>: IsTrue,
        Assert<{ L > 0 }>: IsTrue,
    {
        let mut entry = EntryBase::default();
        entry.set_read(true);
        entry.set_write(true);
        entry.set_exec_super(true);
        entry.set_exec_user(true);
        entry.set_map_memory(true);
        entry.set_typ(0);
        entry.set_phys(
            (mapper.translate_addr(VirtAddr::new(phys)))
                .unwrap()
                .as_u64()
                >> 12,
        );

        Self { entry }
    }
}

pub type Lv4Entry = TableEntry<4>;
pub type Lv3Entry = TableEntry<3>;
pub type Lv2Entry = TableEntry<2>;
pub type Lv1Entry = TableEntry<1>;

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
