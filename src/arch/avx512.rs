#[cfg(feature = "avx512")]
pub(crate) mod avx512_impl {
    use core::arch::x86_64::*;

    use crate::scanner::{ScanAlignment, ScanContext};
    use crate::result::ConstScanResult;

    #[target_feature(enable = "avx512f,avx512bw")]
    unsafe fn load_sig_512(sig: &[crate::signature::SignatureElement]) -> (__m512i, __m512i) {
        let mut bytes = [0u8; 64];
        let mut mask = [0u8; 64];
        for (i, e) in sig.iter().enumerate().take(64) {
            bytes[i] = e.value();
            mask[i] = e.mask();
        }
        (
            _mm512_loadu_si512(bytes.as_ptr() as *const i32),
            _mm512_loadu_si512(mask.as_ptr() as *const i32),
        )
    }

    #[target_feature(enable = "avx512f,avx512bw")]
    unsafe fn align_up_64(ptr: *const u8) -> *const u8 {
        let addr = ptr as usize;
        let rem = addr & 63;
        if rem == 0 { ptr } else { ptr.add(64 - rem) }
    }

    pub(crate) unsafe fn scan_avx512(
        begin: *const u8,
        end: *const u8,
        ctx: &ScanContext,
    ) -> ConstScanResult {
        let sig = ctx.signature;
        let alignment = ctx.alignment;
        let use_pair = ctx.pair_index.is_some();
        let cmp_index = ctx.pair_index.unwrap_or(ctx.cmp_index);
        let veccmp = sig.len() <= 64;
        let sig_size = sig.len();

        let first_byte = _mm512_set1_epi8(sig[cmp_index].value() as i8);

        let second_byte = if use_pair {
            _mm512_set1_epi8(sig[cmp_index + 1].value() as i8)
        } else {
            _mm512_setzero_si512()
        };

        let (sig_bytes, sig_mask) = if veccmp {
            load_sig_512(sig)
        } else {
            (_mm512_setzero_si512(), _mm512_setzero_si512())
        };

        let vec_start = align_up_64(begin.add(cmp_index)) as *const __m512i;
        if vec_start.is_null() || (vec_start as *const u8) > end {
            return crate::scanner::scan_single_raw(begin, end, sig, cmp_index);
        }

        let vec_available = (end as usize).wrapping_sub(vec_start as *const u8 as usize);
        let required = if veccmp { 64usize } else { sig_size };
        let vec_count = if vec_available >= required {
            (vec_available - required) / 64
        } else {
            0
        };
        if vec_count == 0 {
            return crate::scanner::scan_single_raw(begin, end, sig, cmp_index);
        }

        let pre_end = (vec_start as *const u8).sub(cmp_index).add(sig_size);
        if pre_end > begin {
            let result = crate::scanner::scan_single_raw(begin, pre_end, sig, cmp_index);
            if result.has_result() {
                return result;
            }
        }

        let vec_it_end = vec_start.add(vec_count);
        let mut it = vec_start;

        while it < vec_it_end {
            let data = _mm512_load_si512(it);
            let mut mask: u64 = _mm512_cmpeq_epi8_mask(first_byte, data);

            if use_pair {
                let mask2: u64 = _mm512_cmpeq_epi8_mask(second_byte, data);
                mask &= (mask2 >> 1) | (0b1u64 << 63);
            }

            if alignment == ScanAlignment::X16 {
                let align_mask = create_align_mask_64(cmp_index);
                mask &= align_mask;
                if mask == 0 { it = it.add(1); continue; }
            }

            while mask != 0 {
                let offset = mask.trailing_zeros() as usize;
                let i = (it as *const u8).add(offset).sub(cmp_index);

                let matched = if veccmp {
                    let data = _mm512_loadu_si512(i as *const i32);
                    let neq = _mm512_xor_si512(data, sig_bytes);
                    _mm512_test_epi64_mask(neq, sig_mask) == 0
                } else {
                    sig.iter().enumerate().all(|(j, e)| e.matches(*i.add(j)))
                };

                if matched {
                    return ConstScanResult::new(i);
                }
                mask &= mask.wrapping_sub(1);
            }

            it = it.add(1);
        }

        let post_begin = (vec_it_end as *const u8).sub(cmp_index);
        if post_begin < end {
            return crate::scanner::scan_single_raw(post_begin, end, sig, cmp_index);
        }

        ConstScanResult::null()
    }

    fn create_align_mask_64(cmp_index: usize) -> u64 {
        let mut mask: u64 = 0;
        let mut i = cmp_index % 64;
        while i < 64 {
            mask |= 1u64 << i;
            i += 16;
        }
        mask
    }
}

#[cfg(not(feature = "avx512"))]
pub(crate) mod avx512_impl {
    use crate::scanner::ScanContext;
    use crate::result::ConstScanResult;

    pub(crate) unsafe fn scan_avx512(
        _begin: *const u8,
        _end: *const u8,
        _ctx: &ScanContext,
    ) -> ConstScanResult {
        ConstScanResult::null()
    }
}

pub(crate) use avx512_impl::scan_avx512;
