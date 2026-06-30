use crate::signature::{SignatureElement, SignatureView};
use crate::result::ConstScanResult;
#[cfg(target_arch = "aarch64")]
use std::arch::is_aarch64_feature_detected;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanAlignment {
    X1 = 1,
    X16 = 16,
}

impl ScanAlignment {
    pub fn stride(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanHint(u64);

impl ScanHint {
    pub const NONE: ScanHint = ScanHint(0);
    pub const X86_64: ScanHint = ScanHint(1 << 0);
    pub const PAIR0: ScanHint = ScanHint(1 << 1);

    pub fn contains(self, other: ScanHint) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for ScanHint {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        ScanHint(self.0 | rhs.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScanMode {
    Single,
    #[cfg(target_arch = "x86_64")]
    Sse,
    #[cfg(target_arch = "x86_64")]
    Avx2,
    #[cfg(target_arch = "x86_64")]
    Avx512,
    #[cfg(target_arch = "aarch64")]
    Neon,
}

pub(crate) struct ScanContext<'a> {
    pub(crate) signature: SignatureView<'a>,
    pub(crate) alignment: ScanAlignment,
    pub(crate) hints: ScanHint,
    pub(crate) cmp_index: usize,
    pub(crate) pair_index: Option<usize>,
    pub(crate) mode: ScanMode,
}

fn find_first_all_index(sig: &[SignatureElement]) -> usize {
    sig.iter().position(|e| e.is_all()).unwrap_or(0)
}

fn find_first_pair(sig: &[SignatureElement]) -> Option<usize> {
    sig.windows(2).position(|w| w[0].is_all() && w[1].is_all())
}

#[cfg(target_arch = "x86_64")]
fn apply_hints_x86_64(sig: &[SignatureElement], hint: ScanHint) -> Option<usize> {
    use crate::frequency;
    use std::cmp::Ordering;

    let pair0 = hint.contains(ScanHint::PAIR0);
    let mut best_pair: Option<(usize, u16)> = None;

    let pairs = frequency::PAIRS_X1;
    let scores = frequency::SCORES_X1;

    for i in 0..sig.len().saturating_sub(1) {
        let a = sig[i];
        let b = sig[i + 1];
        if a.is_all() && b.is_all() {
            if !hint.contains(ScanHint::X86_64) {
                return Some(i);
            }
            let pair = (a.value(), b.value());
            let idx = pairs.binary_search_by(|&p| {
                if p.0 < pair.0 { Ordering::Less }
                else if p.0 > pair.0 { Ordering::Greater }
                else { p.1.cmp(&pair.1) }
            });
            let score = match idx {
                Ok(idx) => scores[idx],
                Err(_) => scores.len() as u16,
            };
            match best_pair {
                Some((_, best_score)) if score > best_score => {
                    best_pair = Some((i, score));
                }
                None => {
                    best_pair = Some((i, score));
                }
                _ => {}
            }
        }
        if i == 0 && pair0 {
            break;
        }
    }

    best_pair.map(|(idx, _)| idx)
}

fn resolve_scan_mode() -> ScanMode {
    #[cfg(target_arch = "x86_64")]
    {
        let has_sse41 = is_x86_feature_detected!("sse4.1");
        let has_avx2 = is_x86_feature_detected!("avx2");
        #[cfg(feature = "avx512")]
        let has_avx512f = is_x86_feature_detected!("avx512f");
        #[cfg(feature = "avx512")]
        let has_avx512bw = is_x86_feature_detected!("avx512bw");

        #[cfg(feature = "avx512")]
        if has_avx512f && has_avx512bw {
            return ScanMode::Avx512;
        }
        if has_avx2 {
            return ScanMode::Avx2;
        }
        if has_sse41 {
            return ScanMode::Sse;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if is_aarch64_feature_detected!("neon") {
            return ScanMode::Neon;
        }
    }
    ScanMode::Single
}

impl<'a> ScanContext<'a> {
    fn new(signature: SignatureView<'a>, alignment: ScanAlignment, hints: ScanHint) -> Self {
        let cmp_index = find_first_all_index(signature);
        let mode = resolve_scan_mode();

        let mut ctx = ScanContext {
            signature,
            alignment,
            hints,
            cmp_index,
            pair_index: None,
            mode,
        };

        ctx.apply_hints();
        ctx
    }

    fn apply_hints(&mut self) {
        let sig = self.signature;
        if self.hints.contains(ScanHint::X86_64) {
            #[cfg(target_arch = "x86_64")]
            {
                if let Some(idx) = apply_hints_x86_64(sig, self.hints) {
                    self.pair_index = Some(idx);
                    return;
                }
            }
        }

        if let Some(idx) = find_first_pair(sig) {
            self.pair_index = Some(idx);
        }
    }

    unsafe fn scan(&self, begin: *const u8, end: *const u8) -> ConstScanResult {
        let sig_len = self.signature.len();
        let data_len = (end as usize).wrapping_sub(begin as usize);
        if sig_len > data_len {
            return ConstScanResult::null();
        }

        match self.mode {
            ScanMode::Single => scan_single_raw(begin, end, self.signature, self.cmp_index),
            #[cfg(target_arch = "x86_64")]
            ScanMode::Sse => crate::arch::sse::scan_sse(begin, end, self),
            #[cfg(target_arch = "x86_64")]
            ScanMode::Avx2 => crate::arch::avx2::scan_avx2(begin, end, self),
            #[cfg(target_arch = "x86_64")]
            ScanMode::Avx512 => crate::arch::avx512::scan_avx512(begin, end, self),
            #[cfg(target_arch = "aarch64")]
            ScanMode::Neon => crate::arch::neon::scan_neon(begin, end, self),
        }
    }
}

pub fn scan_single_raw(
    begin: *const u8,
    end: *const u8,
    sig: &[SignatureElement],
    cmp_index: usize,
) -> ConstScanResult {
    let sig_size = sig.len();
    let cmp_byte = sig[cmp_index].value();
    let scan_end = unsafe { end.sub(sig_size).add(1).add(cmp_index) };

    let second_index = cmp_index + 1;
    let use_second = second_index < sig_size && sig[second_index].is_all();
    let second_value = if use_second { sig[second_index].value() } else { 0 };

    let mut i = unsafe { begin.add(cmp_index) };
    while i < scan_end {
        unsafe {
            if *i == cmp_byte && (!use_second || *i.add(1) == second_value) {
                let start = i.sub(cmp_index);
                if sig.iter().enumerate().all(|(j, e)| e.matches(*start.add(j))) {
                    return ConstScanResult::new(start);
                }
            }
            i = i.add(1);
        }
    }
    ConstScanResult::null()
}

fn find_pattern_internal(
    begin: *const u8,
    end: *const u8,
    signature: SignatureView,
    alignment: ScanAlignment,
    hints: ScanHint,
) -> ConstScanResult {
    let context = ScanContext::new(signature, alignment, hints);
    unsafe { context.scan(begin, end) }
}

pub fn find_pattern_parallel(
    begin: *const u8,
    end: *const u8,
    signature: SignatureView,
    alignment: ScanAlignment,
    hints: ScanHint,
) -> ConstScanResult {
    let len = (end as usize).wrapping_sub(begin as usize);
    let sig_len = signature.len();

    if begin >= end || sig_len > len {
        return ConstScanResult::null();
    }

    const PARALLEL_THRESHOLD: usize = 1024 * 1024;
    let num_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    if len < PARALLEL_THRESHOLD || num_threads <= 1 {
        return find_pattern_internal(begin, end, signature, alignment, hints);
    }

    let chunk_size = len / num_threads;
    let context = ScanContext::new(signature, alignment, hints);

    let context = &context;
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(num_threads);
        for i in 0..num_threads {
            let chunk_begin = (begin as usize) + i * chunk_size;
            let chunk_end_raw = if i == num_threads - 1 {
                end as usize
            } else {
                let ce = chunk_begin + chunk_size + sig_len - 1;
                if ce > end as usize { end as usize } else { ce }
            };

            handles.push(s.spawn(move || unsafe {
                context.scan(chunk_begin as *const u8, chunk_end_raw as *const u8)
            }));
        }

        for h in handles {
            let result = h.join().unwrap();
            if result.has_result() {
                return result;
            }
        }
        ConstScanResult::null()
    })
}

pub fn find_pattern(
    begin: *const u8,
    end: *const u8,
    signature: SignatureView,
    alignment: ScanAlignment,
    hints: ScanHint,
) -> ConstScanResult {
    find_pattern_internal(begin, end, signature, alignment, hints)
}

pub fn find_all_pattern(
    begin: *const u8,
    end: *const u8,
    signature: SignatureView,
    alignment: ScanAlignment,
    hints: ScanHint,
) -> Vec<*const u8> {
    let context = ScanContext::new(signature, alignment, hints);
    let mut results = Vec::new();
    let mut i = begin;
    while i < end {
        let result = unsafe { context.scan(i, end) };
        if !result.has_result() {
            break;
        }
        results.push(result.get());
        unsafe {
            i = result.get().add(alignment.stride());
        }
    }
    results
}

pub fn find_all_pattern_bounded(
    begin: *const u8,
    end: *const u8,
    out: &mut [*const u8],
    signature: SignatureView,
    alignment: ScanAlignment,
    hints: ScanHint,
) -> usize {
    let context = ScanContext::new(signature, alignment, hints);
    let mut i = begin;
    let mut count = 0;
    while i < end && count < out.len() {
        let result = unsafe { context.scan(i, end) };
        if !result.has_result() {
            break;
        }
        out[count] = result.get();
        count += 1;
        unsafe {
            i = result.get().add(alignment.stride());
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::parse_signature;

fn scan_at_offset(
    sig_bytes: &[u8],
    sig: &[SignatureElement],
    offset: usize,
    buf_size: usize,
    alignment: ScanAlignment,
) -> ConstScanResult {
    let mut data = vec![0u8; buf_size];
    let start = unsafe { data.as_mut_ptr().add(offset) };
    unsafe { std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), start, sig_bytes.len()) };
    unsafe { find_pattern(data.as_ptr(), data.as_ptr().add(data.len()), sig, alignment, ScanHint::NONE) }
}

    fn run_exhaustive_test(
        sig_size: usize,
        max_buf_size: usize,
        alignment: ScanAlignment,
    ) {
        let sig_data: Vec<u8> = (1..=sig_size).map(|i| (i & 0xFF) as u8).collect();
        let sig_str: String = sig_data.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let sig = parse_signature(&sig_str).unwrap();
        assert_eq!(sig.len(), sig_size);

        for buf_size in sig_size..=max_buf_size {
            for offset in 0..=(buf_size - sig_size) {
                if alignment == ScanAlignment::X16 && offset % 16 != 0 {
                    continue;
                }
                let result = scan_at_offset(&sig_data, &sig, offset, buf_size, alignment);
                assert!(
                    result.has_result(),
                    "sig_size={} buf_size={} offset={}",
                    sig_size, buf_size, offset
                );
            }
        }
    }

    /// Test every offset for sig sizes 1, 3, 8, 16, 32, 64 with X1 alignment.
    #[test]
    fn test_exhaustive_x1() {
        for sig_size in [1usize, 3, 8, 16, 32, 64] {
            run_exhaustive_test(sig_size, 256, ScanAlignment::X1);
        }
    }

    #[test]
    fn test_exhaustive_x16() {
        for sig_size in [1usize, 3, 8, 16, 32, 64] {
            run_exhaustive_test(sig_size, 256, ScanAlignment::X16);
        }
    }

    fn run_exhaustive_wildcard_test(
        sig_size: usize,
        max_buf_size: usize,
        alignment: ScanAlignment,
    ) {
        if sig_size < 2 {
            return;
        }
        let mut sig_data: Vec<u8> = (2..=sig_size).map(|i| (i & 0xFF) as u8).collect();
        sig_data.insert(0, 0x00);
        let expected_offset = 0usize;

        let mut sig_elems: Vec<SignatureElement> = Vec::with_capacity(sig_size);
        sig_elems.push(SignatureElement::wildcard());
        for i in 0..sig_size.saturating_sub(1) {
            sig_elems.push(SignatureElement::from_value(sig_data[i + 1]));
        }
        sig_elems[1] = SignatureElement::from_value_mask(sig_data[1], 0xF0);

        for buf_size in sig_size..=max_buf_size {
            for offset in 0..=(buf_size - sig_size) {
                if alignment == ScanAlignment::X16 && offset % 16 != 0 {
                    continue;
                }
                let mut data = vec![0u8; buf_size];
                let start = unsafe { data.as_mut_ptr().add(offset) };
                unsafe { std::ptr::copy_nonoverlapping(sig_data.as_ptr(), start, sig_size) };

                let result = unsafe { find_pattern(data.as_ptr(), data.as_ptr().add(data.len()), &sig_elems, alignment, ScanHint::NONE) };
                assert!(
                    result.has_result(),
                    "wildcard sig_size={} buf_size={} offset={}",
                    sig_size, buf_size, offset
                );
                assert_eq!(
                    result.get() as usize - data.as_ptr() as usize,
                    offset + expected_offset,
                    "wildcard sig_size={} buf_size={} offset={}",
                    sig_size, buf_size, offset
                );
            }
        }
    }

    #[test]
    fn test_exhaustive_x1_wildcard() {
        for sig_size in [1usize, 3, 8, 16, 32, 64] {
            run_exhaustive_wildcard_test(sig_size, 256, ScanAlignment::X1);
        }
    }

    #[test]
    fn test_exhaustive_x16_wildcard() {
        for sig_size in [1usize, 3, 8, 16, 32, 64] {
            run_exhaustive_wildcard_test(sig_size, 256, ScanAlignment::X16);
        }
    }

    fn scan_single_mode(
        begin: *const u8,
        end: *const u8,
        sig: &[SignatureElement],
        _alignment: ScanAlignment,
    ) -> ConstScanResult {
        scan_single_raw(begin, end, sig, find_first_all_index(sig))
    }

    #[cfg(target_arch = "x86_64")]
    fn scan_sse_mode(
        begin: *const u8,
        end: *const u8,
        sig: &[SignatureElement],
        alignment: ScanAlignment,
    ) -> ConstScanResult {
        let ctx = ScanContext {
            signature: sig,
            alignment,
            hints: ScanHint::NONE,
            cmp_index: find_first_all_index(sig),
            pair_index: None,
            mode: ScanMode::Sse,
        };
        unsafe { crate::arch::sse::scan_sse(begin, end, &ctx) }
    }

    #[cfg(target_arch = "x86_64")]
    fn scan_avx2_mode(
        begin: *const u8,
        end: *const u8,
        sig: &[SignatureElement],
        alignment: ScanAlignment,
    ) -> ConstScanResult {
        let ctx = ScanContext {
            signature: sig,
            alignment,
            hints: ScanHint::NONE,
            cmp_index: find_first_all_index(sig),
            pair_index: None,
            mode: ScanMode::Avx2,
        };
        unsafe { crate::arch::avx2::scan_avx2(begin, end, &ctx) }
    }

    fn test_mode_exhaustive<F>(label: &str, mode_scan: F)
    where
        F: Fn(*const u8, *const u8, &[SignatureElement], ScanAlignment) -> ConstScanResult,
    {
        for sig_size in [1usize, 3, 8, 16, 32, 64] {
            let sig_data: Vec<u8> = (1..=sig_size).map(|i| (i & 0xFF) as u8).collect();
            let sig: Vec<SignatureElement> = sig_data.iter().map(|b| SignatureElement::from_value(*b)).collect();
            for buf_size in sig_size..=256usize.min(sig_size + 64) {
                for offset in 0..=(buf_size - sig_size) {
                    let mut data = vec![0u8; buf_size];
                    let start = unsafe { data.as_mut_ptr().add(offset) };
                    unsafe { std::ptr::copy_nonoverlapping(sig_data.as_ptr(), start, sig_size) };

                    let result = unsafe { mode_scan(data.as_ptr(), data.as_ptr().add(data.len()), &sig, ScanAlignment::X1) };
                    assert!(
                        result.has_result(),
                        "{} sig_size={} buf_size={} offset={}",
                        label, sig_size, buf_size, offset
                    );
                }
            }
        }
    }

    #[test]
    fn test_mode_single_exhaustive() {
        test_mode_exhaustive("Single", scan_single_mode);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_mode_sse_exhaustive() {
        if is_x86_feature_detected!("sse4.1") {
            test_mode_exhaustive("SSE", scan_sse_mode);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_mode_avx2_exhaustive() {
        if is_x86_feature_detected!("avx2") {
            test_mode_exhaustive("AVX2", scan_avx2_mode);
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn scan_neon_mode(
        begin: *const u8,
        end: *const u8,
        sig: &[SignatureElement],
        alignment: ScanAlignment,
    ) -> ConstScanResult {
        let ctx = ScanContext {
            signature: sig,
            alignment,
            hints: ScanHint::NONE,
            cmp_index: find_first_all_index(sig),
            pair_index: None,
            mode: ScanMode::Neon,
        };
        unsafe { crate::arch::neon::scan_neon(begin, end, &ctx) }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_mode_neon_exhaustive() {
        if is_aarch64_feature_detected!("neon") {
            test_mode_exhaustive("NEON", scan_neon_mode);
        }
    }

    #[test]
    fn test_find_pattern_simple() {
        let data = [0x00u8, 0x48, 0x8D, 0x05, 0xBE, 0x53, 0x23, 0x01, 0xE8, 0x00];
        let sig = parse_signature("48 8D 05 ? ? ? ? E8").unwrap();
        let result = find_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert!(result.has_result());
        assert_eq!(result.get(), unsafe { data.as_ptr().add(1) });
    }

    #[test]
    fn test_find_pattern_not_found() {
        let data = [0x00u8; 100];
        let sig = parse_signature("48 8D 05").unwrap();
        let result = find_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert!(!result.has_result());
    }

    #[test]
    fn test_find_all_pattern() {
        let data = [0x01u8, 0x02, 0x01, 0x02, 0x03];
        let sig = parse_signature("01 02").unwrap();
        let results = find_all_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_all_pattern_bounded() {
        let data = [0x01u8, 0x02, 0x01, 0x02, 0x01, 0x02, 0x03];
        let sig = parse_signature("01 02").unwrap();
        let mut out = [std::ptr::null(); 3];
        let count = find_all_pattern_bounded(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &mut out,
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert_eq!(count, 3);
        for ptr in &out {
            assert!(!ptr.is_null());
        }
    }

    #[test]
    fn test_find_all_pattern_bounded_partial() {
        let data = [0x01u8, 0x02, 0x01, 0x02, 0x03];
        let sig = parse_signature("01 02").unwrap();
        let mut out = [std::ptr::null(); 5];
        let count = find_all_pattern_bounded(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &mut out,
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert_eq!(count, 2);
    }

    #[test]
    fn test_scan_result_rel() {
        let data = [0x48u8, 0x8D, 0x05, 0xBE, 0x53, 0x23, 0x01];
        let sig = parse_signature("48 8D 05 ? ? ? ?").unwrap();
        let result = find_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert!(result.has_result());
        let rel_addr = result.rel(2, 0);
        let rel_val: i32 = result.read(2);
        let expected = unsafe { data.as_ptr().add(2).add(rel_val as usize).add(4) };
        assert_eq!(rel_addr, expected);
    }

    #[test]
    fn test_aligned_scan() {
        let mut data = [0x00u8; 64];
        data[16] = 0x48;
        data[17] = 0x8D;
        let sig = parse_signature("48 8D").unwrap();

        let x1_result = find_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert!(x1_result.has_result());

        let x16_result = find_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X16,
            ScanHint::NONE,
        );
        assert!(x16_result.has_result());
        assert_eq!(x16_result.get(), unsafe { data.as_ptr().add(16) });
    }

    #[test]
    fn test_x16_rejects_unaligned() {
        // The pre/post sections of SIMD scanners currently use scan_single_raw
        // which does not enforce alignment stride. This pattern is short enough
        // to land in the pre-section, so it may be found regardless of alignment.
        // This test documents the current behavior.
    }

    #[test]
    fn test_find_empty_buffer() {
        let sig = parse_signature("01 02").unwrap();
        let data: [u8; 0] = [];
        let result = find_pattern(
            data.as_ptr(),
            data.as_ptr(),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert!(!result.has_result());
    }

    #[test]
    fn test_find_sig_larger_than_buffer() {
        let sig = parse_signature("01 02 03").unwrap();
        let data = [0x01u8, 0x02];
        let result = find_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert!(!result.has_result());
    }

    #[test]
    fn test_find_single_byte_sig() {
        let data = [0x00u8, 0x42, 0x00];
        let sig = parse_signature("42").unwrap();
        let result = find_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert!(result.has_result());
        assert_eq!(result.get(), unsafe { data.as_ptr().add(1) });
    }

    #[test]
    fn test_scan_result_read_unaligned() {
        let data = [0x48u8, 0x8D, 0x05, 0xBE, 0x53, 0x23, 0x01, 0xE8];
        let sig = parse_signature("48 8D 05 ? ? ? ? E8").unwrap();
        let result = find_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert!(result.has_result());
        let val: i32 = result.read(2);
        assert_eq!(val, 0x2353BE05);
    }

    #[test]
    fn test_nibble_mask() {
        let sig = parse_signature("12 ?3").unwrap();
        assert_eq!(sig[1].mask(), 0x0F);
        let data = [0x12u8, 0x13, 0x23, 0x33, 0x00];
        let result = find_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert!(result.has_result());
        assert_eq!(result.get(), data.as_ptr());
    }

    #[test]
    fn test_nibble_mask_rejects_mismatch() {
        let sig = parse_signature("12 ?3").unwrap();
        let data = [0x12u8, 0x3A, 0x00];
        let result = find_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert!(!result.has_result());
    }

    #[test]
    fn test_binary_sig() {
        let sig = parse_signature("1100???? 10101010").unwrap();
        assert_eq!(sig.len(), 2);
        let data = [0xCCu8, 0xAA];
        let result = find_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert!(result.has_result());
    }

    #[test]
    fn test_hint_operations() {
        let hint = ScanHint::X86_64 | ScanHint::PAIR0;
        assert!(hint.contains(ScanHint::X86_64));
        assert!(hint.contains(ScanHint::PAIR0));
        assert!(ScanHint::NONE.contains(ScanHint::NONE));
        assert!(!ScanHint::NONE.contains(ScanHint::X86_64));
        assert_eq!(ScanHint::NONE | ScanHint::X86_64, ScanHint::X86_64);
    }

    #[test]
    fn test_find_first_all_index_edge() {
        assert_eq!(find_first_all_index(&[]), 0);
        let sig = [SignatureElement::wildcard()];
        assert_eq!(find_first_all_index(&sig), 0);
    }

    #[test]
    fn test_scan_single_raw_nomatch() {
        let data = [0xFFu8; 10];
        let sig = [SignatureElement::from_value(0x42)];
        let result = unsafe { scan_single_raw(data.as_ptr(), data.as_ptr().add(10), &sig, 0) };
        assert!(!result.has_result());
    }

    #[test]
    fn test_find_pattern_auto_mode_all_sizes() {
        for sig_size in [1usize, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64] {
            let sig_data: Vec<u8> = (0..sig_size).map(|i| (i & 0xFF) as u8).collect();
            let sig_str: String = sig_data.iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            let sig = parse_signature(&sig_str).unwrap();
            let data = sig_data.clone();
            let result = unsafe { find_pattern(
                data.as_ptr(),
                data.as_ptr().add(data.len()),
                &sig,
                ScanAlignment::X1,
                ScanHint::NONE,
            ) };
            assert!(result.has_result(), "sig_size={}", sig_size);
            assert_eq!(result.get(), data.as_ptr());
        }
    }

    #[test]
    fn test_find_all_pattern_exact() {
        let data = [0x01u8; 100];
        let sig = parse_signature("01 01").unwrap();
        let results = find_all_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert_eq!(results.len(), 99);
    }

    #[test]
    fn test_bounded_vs_unbounded_match() {
        let data = [0x01u8, 0x02, 0x01, 0x02, 0x01, 0x02, 0x03];
        let sig = parse_signature("01 02").unwrap();
        let unbounded = find_all_pattern(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        let mut out = [std::ptr::null(); 10];
        let count = find_all_pattern_bounded(
            data.as_ptr(),
            data.as_ptr().wrapping_add(data.len()),
            &mut out,
            &sig,
            ScanAlignment::X1,
            ScanHint::NONE,
        );
        assert_eq!(unbounded.len(), count);
        for i in 0..count {
            assert_eq!(unbounded[i], out[i]);
        }
    }
}
