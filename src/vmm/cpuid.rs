use raw_cpuid::cpuid;

use super::{vcpu::VCpu, vmcs::VmxLeaf};

pub fn handle_cpuid_exit(vcpu: &mut VCpu) {
    let regs = &mut vcpu.guest_registers;
    //let vendor: &[u8; 12] = b"miHypervisor";
    let vendor: &[u8; 12] = b"KVMKVMKVMKVM";

    let vendor = unsafe { core::mem::transmute::<&[u8; 12], &[u32; 3]>(vendor) };
    match VmxLeaf::from(regs.rax) {
        VmxLeaf::EXTENDED_FEATURE => match regs.rcx {
            0 => {
                let mut ebx = ExtFeatureEbx0::default();
                ebx.smep = true;
                ebx.invpcid = false;
                ebx.smap = true;
                regs.rax = 1;
                regs.rbx = ebx.as_u32() as u64;
                regs.rcx = 0;
                regs.rdx = 0;
            }
            1 => {
                invalid(vcpu);
            }
            2 => {
                invalid(vcpu);
            }
            _ => {
                panic!("Unhandled CPUID leaf: {:#x}.{:#x}", regs.rax, regs.rcx);
            }
        },
        VmxLeaf::EXTENDED_PROCESSOR_SIGNATURE => {
            let signature = cpuid!(0x80000001, 0);
            regs.rax = 0x00000000;
            regs.rbx = 0x00000000;
            regs.rcx = signature.ecx as u64;
            regs.rdx = signature.edx as u64;
        }
        VmxLeaf::EXTENDED_FUNCTION => {
            regs.rax = 0x80000000 + 1;
            regs.rbx = 0x00000000;
            regs.rcx = 0x00000000;
            regs.rdx = 0x00000000;
        }
        VmxLeaf::MAXIMUM_INPUT => {
            regs.rax = 0x20;
            regs.rbx = vendor[0] as u64;
            regs.rcx = vendor[2] as u64;
            regs.rdx = vendor[1] as u64;
        }
        VmxLeaf::VERSION_AND_FEATURE_INFO => {
            let ecx = FeatureInfoEcx {
                sse3: false,
                pclmulqdq: false,
                dtes64: false,
                monitor: false,
                ds_cpl: false,
                vmx: false,
                smx: false,
                eist: false,
                tm2: false,
                ssse3: false,
                cnxt_id: false,
                sdbg: false,
                fma: false,
                cmpxchg16b: false,
                xtpr: false,
                pdcm: false,
                _reserved_0: false,
                pcid: true,
                dca: false,
                sse4_1: false,
                sse4_2: false,
                x2apic: false,
                movbe: false,
                popcnt: false,
                tsc_deadline: false,
                aesni: false,
                xsave: false,
                osxsave: false,
                avx: false,
                f16c: false,
                rdrand: false,
                hypervisor: false,
            };
            let edx = FeatureInfoEdx {
                fpu: true,
                vme: true,
                de: true,
                pse: true,
                tsc: false,
                msr: true,
                pae: true,
                mce: false,
                cx8: true,
                apic: false,
                _reserved_0: false,
                sep: true,
                mtrr: false,
                pge: true,
                mca: false,
                cmov: true,
                pat: false,
                pse36: true,
                psn: false,
                clfsh: false,
                _reserved_1: false,
                ds: false,
                acpi: true,
                mmx: false,
                fxsr: true,
                sse: true,
                sse2: true,
                ss: false,
                htt: false,
                tm: false,
                _reserved_2: false,
                pbe: false,
            };
            let cpuid = cpuid!(0x1, 0);
            regs.rax = cpuid.eax as u64;
            regs.rbx = cpuid.ebx as u64;
            regs.rcx = ecx.to_u32() as u64;
            regs.rdx = edx.to_u32() as u64;
        }
        _ => {
            invalid(vcpu);
        }
    };
}

fn invalid(vcpu: &mut VCpu) {
    let regs = &mut vcpu.guest_registers;

    regs.rax = 0;
    regs.rbx = 0;
    regs.rcx = 0;
    regs.rdx = 0;
}

#[derive(Default)]
#[repr(C, packed)]
pub struct FeatureInfoEcx {
    pub sse3: bool,
    pub pclmulqdq: bool,
    pub dtes64: bool,
    pub monitor: bool,
    pub ds_cpl: bool,
    pub vmx: bool,
    pub smx: bool,
    pub eist: bool,
    pub tm2: bool,
    pub ssse3: bool,
    pub cnxt_id: bool,
    pub sdbg: bool,
    pub fma: bool,
    pub cmpxchg16b: bool,
    pub xtpr: bool,
    pub pdcm: bool,
    pub _reserved_0: bool,
    pub pcid: bool,
    pub dca: bool,
    pub sse4_1: bool,
    pub sse4_2: bool,
    pub x2apic: bool,
    pub movbe: bool,
    pub popcnt: bool,
    pub tsc_deadline: bool,
    pub aesni: bool,
    pub xsave: bool,
    pub osxsave: bool,
    pub avx: bool,
    pub f16c: bool,
    pub rdrand: bool,
    pub hypervisor: bool,
}

impl FeatureInfoEcx {
    pub fn to_u32(&self) -> u32 {
        (self.sse3 as u32) << 0
            | (self.pclmulqdq as u32) << 1
            | (self.dtes64 as u32) << 2
            | (self.monitor as u32) << 3
            | (self.ds_cpl as u32) << 4
            | (self.vmx as u32) << 5
            | (self.smx as u32) << 6
            | (self.eist as u32) << 7
            | (self.tm2 as u32) << 8
            | (self.ssse3 as u32) << 9
            | (self.cnxt_id as u32) << 10
            | (self.sdbg as u32) << 11
            | (self.fma as u32) << 12
            | (self.cmpxchg16b as u32) << 13
            | (self.xtpr as u32) << 14
            | (self.pdcm as u32) << 15
            | (self._reserved_0 as u32) << 16
            | (self.pcid as u32) << 17
            | (self.dca as u32) << 18
            | (self.sse4_1 as u32) << 19
            | (self.sse4_2 as u32) << 20
            | (self.x2apic as u32) << 21
            | (self.movbe as u32) << 22
            | (self.popcnt as u32) << 23
            | (self.tsc_deadline as u32) << 24
            | (self.aesni as u32) << 25
            | (self.xsave as u32) << 26
            | (self.osxsave as u32) << 27
            | (self.avx as u32) << 28
            | (self.f16c as u32) << 29
            | (self.rdrand as u32) << 30
            | (self.hypervisor as u32) << 31
    }
}

#[derive(Default)]
#[repr(C, packed)]
pub struct FeatureInfoEdx {
    pub fpu: bool,
    pub vme: bool,
    pub de: bool,
    pub pse: bool,
    pub tsc: bool,
    pub msr: bool,
    pub pae: bool,
    pub mce: bool,
    pub cx8: bool,
    pub apic: bool,
    pub _reserved_0: bool,
    pub sep: bool,
    pub mtrr: bool,
    pub pge: bool,
    pub mca: bool,
    pub cmov: bool,
    pub pat: bool,
    pub pse36: bool,
    pub psn: bool,
    pub clfsh: bool,
    pub _reserved_1: bool,
    pub ds: bool,
    pub acpi: bool,
    pub mmx: bool,
    pub fxsr: bool,
    pub sse: bool,
    pub sse2: bool,
    pub ss: bool,
    pub htt: bool,
    pub tm: bool,
    pub _reserved_2: bool,
    pub pbe: bool,
}

impl FeatureInfoEdx {
    pub fn to_u32(&self) -> u32 {
        (self.fpu as u32) << 0
            | (self.vme as u32) << 1
            | (self.de as u32) << 2
            | (self.pse as u32) << 3
            | (self.tsc as u32) << 4
            | (self.msr as u32) << 5
            | (self.pae as u32) << 6
            | (self.mce as u32) << 7
            | (self.cx8 as u32) << 8
            | (self.apic as u32) << 9
            | (self._reserved_0 as u32) << 10
            | (self.sep as u32) << 11
            | (self.mtrr as u32) << 12
            | (self.pge as u32) << 13
            | (self.mca as u32) << 14
            | (self.cmov as u32) << 15
            | (self.pat as u32) << 16
            | (self.pse36 as u32) << 17
            | (self.psn as u32) << 18
            | (self.clfsh as u32) << 19
            | (self._reserved_1 as u32) << 20
            | (self.ds as u32) << 21
            | (self.acpi as u32) << 22
            | (self.mmx as u32) << 23
            | (self.fxsr as u32) << 24
            | (self.sse as u32) << 25
            | (self.sse2 as u32) << 26
            | (self.ss as u32) << 27
            | (self.htt as u32) << 28
            | (self.tm as u32) << 29
            | (self._reserved_2 as u32) << 30
            | (self.pbe as u32) << 31
    }
}

#[derive(Debug)]
pub struct ExtFeatureEbx0 {
    pub fsgsbase: bool,
    pub tsc_adjust: bool,
    pub sgx: bool,
    pub bmi1: bool,
    pub hle: bool,
    pub avx2: bool,
    pub fdp: bool,
    pub smep: bool,
    pub bmi2: bool,
    pub erms: bool,
    pub invpcid: bool,
    pub rtm: bool,
    pub rdtm: bool,
    pub fpucsds: bool,
    pub mpx: bool,
    pub rdta: bool,
    pub avx512f: bool,
    pub avx512dq: bool,
    pub rdseed: bool,
    pub adx: bool,
    pub smap: bool,
    pub avx512ifma: bool,
    pub _reserved1: bool,
    pub clflushopt: bool,
    pub clwb: bool,
    pub pt: bool,
    pub avx512pf: bool,
    pub avx512er: bool,
    pub avx512cd: bool,
    pub sha: bool,
    pub avx512bw: bool,
    pub avx512vl: bool,
}

impl Default for ExtFeatureEbx0 {
    fn default() -> Self {
        Self {
            fsgsbase: false,
            tsc_adjust: false,
            sgx: false,
            bmi1: false,
            hle: false,
            avx2: false,
            fdp: false,
            smep: false,
            bmi2: false,
            erms: false,
            invpcid: false,
            rtm: false,
            rdtm: false,
            fpucsds: false,
            mpx: false,
            rdta: false,
            avx512f: false,
            avx512dq: false,
            rdseed: false,
            adx: false,
            smap: false,
            avx512ifma: false,
            _reserved1: false,
            clflushopt: false,
            clwb: false,
            pt: false,
            avx512pf: false,
            avx512er: false,
            avx512cd: false,
            sha: false,
            avx512bw: false,
            avx512vl: false,
        }
    }
}

impl ExtFeatureEbx0 {
    pub fn as_u32(&self) -> u32 {
        (self.fsgsbase as u32)
            | (self.tsc_adjust as u32) << 1
            | (self.sgx as u32) << 2
            | (self.bmi1 as u32) << 3
            | (self.hle as u32) << 4
            | (self.avx2 as u32) << 5
            | (self.fdp as u32) << 6
            | (self.smep as u32) << 7
            | (self.bmi2 as u32) << 8
            | (self.erms as u32) << 9
            | (self.invpcid as u32) << 10
            | (self.rtm as u32) << 11
            | (self.rdtm as u32) << 12
            | (self.fpucsds as u32) << 13
            | (self.mpx as u32) << 14
            | (self.rdta as u32) << 15
            | (self.avx512f as u32) << 16
            | (self.avx512dq as u32) << 17
            | (self.rdseed as u32) << 18
            | (self.adx as u32) << 19
            | (self.smap as u32) << 20
            | (self.avx512ifma as u32) << 21
            | (self._reserved1 as u32) << 22
            | (self.clflushopt as u32) << 23
            | (self.clwb as u32) << 24
            | (self.pt as u32) << 25
            | (self.avx512pf as u32) << 26
            | (self.avx512er as u32) << 27
            | (self.avx512cd as u32) << 28
            | (self.sha as u32) << 29
            | (self.avx512bw as u32) << 30
            | (self.avx512vl as u32) << 31
    }
}
