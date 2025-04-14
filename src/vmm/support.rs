pub fn has_intel_cpu() -> bool {
    let cpuid = x86::cpuid::CpuId::new();
    if let Some(vi) = cpuid.get_vendor_info() {
        if vi.as_str() == "GenuineIntel" {
            return true;
        }
    }
    false
}

pub fn has_vmx_support() -> bool {
    let cpuid = x86::cpuid::CpuId::new();
    if let Some(fi) = cpuid.get_feature_info() {
        if fi.has_vmx() {
            return true;
        }
    }
    false
}
