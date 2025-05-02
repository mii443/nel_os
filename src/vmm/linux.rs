use core::ptr::read_unaligned;

pub const BZIMAGE: &'static [u8] = include_bytes!("../../bzImage");

pub const LAYOUT_BOOTPARAM: u64 = 0x0001_0000;
pub const LAYOUT_CMDLINE: u64 = 0x0002_0000;
pub const LAYOUT_KERNEL_BASE: u64 = 0x0010_0000;
pub const LAYOUT_INITRD: u64 = 0x0600_0000;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BootParams {
    pub _screen_info: [u8; 0x40],
    pub _apm_bios_info: [u8; 0x14],
    pub _pad2: [u8; 4],
    pub tboot_addr: u64,
    pub ist_info: [u8; 0x10],
    pub _pad3: [u8; 0x10],
    pub hd0_info: [u8; 0x10],
    pub hd1_info: [u8; 0x10],
    pub _sys_desc_table: [u8; 0x10],
    pub _olpc_ofw_header: [u8; 0x10],
    pub _pad4: [u8; 0x80],
    pub _edid_info: [u8; 0x80],
    pub _efi_info: [u8; 0x20],
    pub alt_mem_k: u32,
    pub scratch: u32,
    pub e820_entries: u8,
    pub eddbuf_entries: u8,
    pub edd_mbr_sig_buf_entries: u8,
    pub kbd_status: u8,
    pub _pad6: [u8; 5],
    pub hdr: SetupHeader,
    pub _pad7: [u8; 0x290 - SetupHeader::HEADER_OFFSET - size_of::<SetupHeader>()],
    pub _edd_mbr_sig_buffer: [u32; 0x10],
    pub e820_map: [E820Entry; Self::E820MAX],
    pub _unimplemented: [u8; 0x330],
}

impl BootParams {
    pub const E820MAX: usize = 128;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < size_of::<Self>() {
            return Err("バイト配列が小さすぎます");
        }

        unsafe {
            let boot_params_ptr = bytes.as_ptr() as *const Self;
            Ok(read_unaligned(boot_params_ptr))
        }
    }

    pub fn add_e820_entry(&mut self, addr: u64, size: u64, type_: E820Type) {
        self.e820_map[self.e820_entries as usize].addr = addr;
        self.e820_map[self.e820_entries as usize].size = size;
        self.e820_map[self.e820_entries as usize].type_ = type_ as u32;
        self.e820_entries += 1;
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SetupHeader {
    pub setup_sects: u8,
    pub root_flags: u16,
    pub syssize: u32,
    pub ram_size: u16,
    pub vid_mode: u16,
    pub root_dev: u16,
    pub boot_flag: u16,
    pub jump: u16,
    pub header: u32,
    pub version: u16,
    pub realmode_switch: u32,
    pub start_sys_seg: u16,
    pub kernel_version: u16,
    pub type_of_loader: u8,
    pub loadflags: LoadflagBitfield,
    pub setup_move_size: u16,
    pub code32_start: u32,
    pub ramdisk_image: u32,
    pub ramdisk_size: u32,
    pub bootsect_kludge: u32,
    pub heap_end_ptr: u16,
    pub ext_loader_ver: u8,
    pub ext_loader_type: u8,
    pub cmd_line_ptr: u32,
    pub initrd_addr_max: u32,
    pub kernel_alignment: u32,
    pub relocatable_kernel: u8,
    pub min_alignment: u8,
    pub xloadflags: u16,
    pub cmdline_size: u32,
    pub hardware_subarch: u32,
    pub hardware_subarch_data: u64,
    pub payload_offset: u32,
    pub payload_length: u32,
    pub setup_data: u64,
    pub pref_address: u64,
    pub init_size: u32,
    pub handover_offset: u32,
    pub kernel_info_offset: u32,
}

impl SetupHeader {
    pub const HEADER_OFFSET: usize = 0x1F1;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < Self::HEADER_OFFSET + size_of::<Self>() {
            return Err("バイト配列が小さすぎます");
        }

        let mut header = unsafe {
            let header_ptr = bytes.as_ptr().add(Self::HEADER_OFFSET) as *const Self;
            read_unaligned(header_ptr)
        };

        if header.setup_sects == 0 {
            header.setup_sects = 4;
        }

        Ok(header)
    }

    pub fn get_protected_code_offset(&self) -> usize {
        (self.setup_sects as usize + 1) * 512
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct LoadflagBitfield {
    raw: u8,
}

impl LoadflagBitfield {
    pub fn loaded_high(&self) -> bool {
        (self.raw & 0x01) != 0
    }

    pub fn set_loaded_high(&mut self, loaded_high: bool) {
        if loaded_high {
            self.raw |= 0x01;
        } else {
            self.raw &= !0x01;
        }
    }

    pub fn kaslr_flag(&self) -> bool {
        (self.raw & 0x02) != 0
    }

    pub fn quiet_flag(&self) -> bool {
        (self.raw & 0x20) != 0
    }

    pub fn keep_segments(&self) -> bool {
        (self.raw & 0x40) != 0
    }

    pub fn set_keep_segments(&mut self, keep_segments: bool) {
        if keep_segments {
            self.raw |= 0x40;
        } else {
            self.raw &= !0x40;
        }
    }

    pub fn can_use_heap(&self) -> bool {
        (self.raw & 0x80) != 0
    }

    pub fn set_can_use_heap(&mut self, can_use_heap: bool) {
        if can_use_heap {
            self.raw |= 0x80;
        } else {
            self.raw &= !0x80;
        }
    }

    pub fn new(
        loaded_high: bool,
        kaslr_flag: bool,
        quiet_flag: bool,
        keep_segments: bool,
        can_use_heap: bool,
    ) -> Self {
        let mut raw = 0u8;
        if loaded_high {
            raw |= 0x01;
        }
        if kaslr_flag {
            raw |= 0x02;
        }
        if quiet_flag {
            raw |= 0x20;
        }
        if keep_segments {
            raw |= 0x40;
        }
        if can_use_heap {
            raw |= 0x80;
        }
        Self { raw }
    }

    pub fn to_u8(&self) -> u8 {
        self.raw
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct E820Entry {
    addr: u64,
    size: u64,
    type_: u32,
}

impl E820Entry {
    pub fn get_addr(&self) -> u64 {
        self.addr
    }

    pub fn get_size(&self) -> u64 {
        self.size
    }

    pub fn get_type(&self) -> Result<E820Type, &'static str> {
        match self.type_ {
            1 => Ok(E820Type::Ram),
            2 => Ok(E820Type::Reserved),
            3 => Ok(E820Type::Acpi),
            4 => Ok(E820Type::Nvs),
            5 => Ok(E820Type::Unusable),
            _ => Err("不明なE820タイプ"),
        }
    }

    pub fn new(addr: u64, size: u64, type_: E820Type) -> Self {
        Self {
            addr,
            size,
            type_: type_ as u32,
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E820Type {
    Ram = 1,
    Reserved = 2,
    Acpi = 3,
    Nvs = 4,
    Unusable = 5,
}
