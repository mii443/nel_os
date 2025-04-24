use bitfield::bitfield;
use x86_64::PhysAddr;

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

    pub fn new_map_table() {}
}
