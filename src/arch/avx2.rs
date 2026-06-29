use core::arch::x86_64::*;

use crate::scanner::{ScanAlignment, ScanContext};
use crate::result::ConstScanResult;

#[target_feature(enable = "avx,avx2")]
unsafe fn load_sig_256(sig: &[crate::signature::SignatureElement]) -> (__m256i, __m256i) {
    let mut bytes = [0u8; 32];
    let mut mask = [0u8; 32];
    for (i, e) in sig.iter().enumerate().take(32) {
        bytes[i] = e.value();
        mask[i] = e.mask();
    }
    (
        _mm256_loadu_si256(bytes.as_ptr() as *const __m256i),
        _mm256_loadu_si256(mask.as_ptr() as *const __m256i),
    )
}

#[target_feature(enable = "avx,avx2")]
unsafe fn align_up_32(ptr: *const u8) -> *const u8 {
    let addr = ptr as usize;
    let rem = addr & 31;
    if rem == 0 { ptr } else { ptr.add(32 - rem) }
}

pub(crate) unsafe fn scan_avx2(
    begin: *const u8,
    end: *const u8,
    ctx: &ScanContext,
) -> ConstScanResult {
    let sig = ctx.signature;
    let alignment = ctx.alignment;
    let use_pair = ctx.pair_index.is_some();
    let cmp_index = ctx.pair_index.unwrap_or(ctx.cmp_index);
    let veccmp = sig.len() <= 32;
    let sig_size = sig.len();

    let first_byte = _mm256_set1_epi8(sig[cmp_index].value() as i8);

    let second_byte = if use_pair {
        _mm256_set1_epi8(sig[cmp_index + 1].value() as i8)
    } else {
        _mm256_setzero_si256()
    };

    let (sig_bytes, sig_mask) = if veccmp {
        load_sig_256(sig)
    } else {
        (_mm256_setzero_si256(), _mm256_setzero_si256())
    };

    let vec_start = align_up_32(begin.add(cmp_index)) as *const __m256i;
    if vec_start.is_null() || (vec_start as *const u8) > end {
        return crate::scanner::scan_single_raw(begin, end, sig, cmp_index);
    }

    let vec_available = (end as usize).wrapping_sub(vec_start as *const u8 as usize);
    let required = if veccmp { 32usize } else { sig_size };
    let vec_count = if vec_available >= required {
        (vec_available - required) / 32
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
        let data = _mm256_load_si256(it);
        let cmp = _mm256_cmpeq_epi8(first_byte, data);
        let mut mask: u32 = _mm256_movemask_epi8(cmp) as u32;

        if use_pair {
            let cmp2 = _mm256_cmpeq_epi8(second_byte, data);
            let mask2: u32 = _mm256_movemask_epi8(cmp2) as u32;
            mask &= (mask2 >> 1) | (0b1u32 << 31);
        }

        if alignment == ScanAlignment::X16 {
            let align_mask = create_align_mask_32(cmp_index);
            mask &= align_mask;
            if mask == 0 { it = it.add(1); continue; }
        }

        while mask != 0 {
            let offset = mask.trailing_zeros() as usize;
            let i = (it as *const u8).add(offset).sub(cmp_index);

            let matched = if veccmp {
                let data = _mm256_loadu_si256(i as *const __m256i);
                let neq = _mm256_xor_si256(data, sig_bytes);
                _mm256_testz_si256(neq, sig_mask) != 0
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

fn create_align_mask_32(cmp_index: usize) -> u32 {
    let mut mask: u32 = 0;
    let mut i = cmp_index % 32;
    while i < 32 {
        mask |= 1u32 << i;
        i += 16;
    }
    mask
}
