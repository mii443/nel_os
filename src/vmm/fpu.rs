use bitfield::bitfield;

use crate::error;

use super::vcpu::VCpu;

bitfield! {
    pub struct XCR0(u64);

    pub x87, set_x87: 0, 1;
    pub sse, set_sse: 1, 1;
    pub avx, set_avx: 2, 1;
    pub bndreg, set_bndreg: 3, 1;
    pub bndcsr, set_bndcsr: 4, 1;
    pub opmask, set_opmask: 5, 1;
    pub zmm_hi256, set_zmm_hi256: 6, 1;
    pub hi16_zmm, set_hi16_zmm: 7, 1;
    pub pt, set_pt: 8, 1;
    pub pkru, set_pkru: 9, 1;
    pub pasid, set_pasid: 10, 1;
    pub cet_u, set_cet_u: 11, 1;
    pub cet_s, set_cet_s: 12, 1;
    pub hdc, set_hdc: 13, 1;
    pub intr, set_intr: 14, 1;
    pub lbr, set_lbr: 15, 1;
    pub hwp, set_hwp: 16, 1;
    pub xtilecfg, set_xtilecfg: 17, 1;
    pub xtiledata, set_xtiledata: 18, 1;
    pub apx, set_apx: 19, 1;
    pub reserved, set_reserved: 20, 44;
}

pub fn set_xcr(vcpu: &mut VCpu, index: u32, xcr: u64) -> Result<(), ()> {
    if index != 0 {
        error!("Invalid XCR index: {}", index);
        return Err(());
    }

    if !(xcr & 0b1 != 0) {
        error!("X87 is not enabled");
        return Err(());
    }

    if (xcr & 0b100 != 0) && !(xcr & 0b10 != 0) {
        error!("SSE is not enabled");
        return Err(());
    }

    if !(xcr & 0b1000) != (!(xcr & 0b10000)) {
        error!("BNDREGS and BNDCSR are not both enabled");
        return Err(());
    }

    if xcr & 0b11100000 != 0 {
        if !(xcr & 0b100 != 0) {
            error!("YMM bits are not enabled");
            return Err(());
        }

        if (xcr & 0b11100000) != 0b11100000 {
            error!("Invalid bits set in XCR0");
            return Err(());
        }
    }

    if (xcr & 0b1000000000000 != 0) && (xcr & 0b1000000000000 != 0b1000000000000) {
        error!("xtile bits are not both enabled");
        return Err(());
    }

    vcpu.xcr0 = XCR0(xcr);

    Ok(())
}
