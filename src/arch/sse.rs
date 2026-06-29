use core::arch::x86_64::*;

use crate::scanner::{ScanAlignment, ScanContext};
use crate::result::ConstScanResult;

#[target_feature(enable = "sse4.1")]
unsafe fn load_sig_128(sig: &[crate::signature::SignatureElement]) -> (__m128i, __m128i) {
    let mut bytes = [0u8; 16];
    let mut mask = [0u8; 16];
    for (i, e) in sig.iter().enumerate().take(16) {
        bytes[i] = e.value();
        mask[i] = e.mask();
    }
    (
        _mm_loadu_si128(bytes.as_ptr() as *const __m128i),
        _mm_loadu_si128(mask.as_ptr() as *const __m128i),
    )
}

#[target_feature(enable = "sse4.1")]
unsafe fn align_up_16(ptr: *const u8) -> *const u8 {
    let addr = ptr as usize;
    let rem = addr & 15;
    if rem == 0 { ptr } else { ptr.add(16 - rem) }
}

#[target_feature(enable = "sse4.1")]
fn bsf_16(mask: u16) -> u32 {
    mask.trailing_zeros()
}

pub(crate) unsafe fn scan_sse(
    begin: *const u8,
    end: *const u8,
    ctx: &ScanContext,
) -> ConstScanResult {
    let sig = ctx.signature;
    let alignment = ctx.alignment;
    let use_pair = ctx.pair_index.is_some();
    let cmp_index = ctx.pair_index.unwrap_or(ctx.cmp_index);
    let veccmp = sig.len() <= 16;
    let sig_size = sig.len();

    let first_byte = _mm_set1_epi8(sig[cmp_index].value() as i8);

    let second_byte = if use_pair {
        _mm_set1_epi8(sig[cmp_index + 1].value() as i8)
    } else {
        _mm_setzero_si128()
    };

    let (sig_bytes, sig_mask) = if veccmp {
        load_sig_128(sig)
    } else {
        (_mm_setzero_si128(), _mm_setzero_si128())
    };

    let vec_start = align_up_16(begin.add(cmp_index)) as *const __m128i;
    if vec_start.is_null() || (vec_start as *const u8) > end {
        return crate::scanner::scan_single_raw(begin, end, sig, cmp_index);
    }

    let vec_available = (end as usize).wrapping_sub(vec_start as *const u8 as usize);
    let required = if veccmp { 16usize } else { sig_size };
    let vec_count = if vec_available >= required {
        (vec_available - required) / 16
    } else {
        0
    };
    if vec_count == 0 {
        return crate::scanner::scan_single_raw(begin, end, sig, cmp_index);
    }

    let pre_end = (vec_start as *const u8).sub(cmp_index).add(sig_size);
    if !pre_end.is_null() && pre_end > begin {
        let result = crate::scanner::scan_single_raw(begin, pre_end, sig, cmp_index);
        if result.has_result() {
            return result;
        }
    }

    let vec_it_end = vec_start.add(vec_count);

    let mut it = vec_start;
    while it < vec_it_end {
        let data = _mm_load_si128(it);
        let cmp = _mm_cmpeq_epi8(first_byte, data);
        let mut mask: u16 = _mm_movemask_epi8(cmp) as u16;

        if use_pair {
            let cmp2 = _mm_cmpeq_epi8(second_byte, data);
            let mask2: u16 = _mm_movemask_epi8(cmp2) as u16;
            mask &= (mask2 >> 1) | (0b1u16 << 15);
        }

        if alignment == ScanAlignment::X16 {
            let align_mask = create_align_mask_16(cmp_index);
            mask &= align_mask;
        }

        while mask != 0 {
            let offset = bsf_16(mask) as usize;
            let i = (it as *const u8).add(offset).sub(cmp_index);

            let matched = if veccmp {
                let data = _mm_loadu_si128(i as *const __m128i);
                let neq = _mm_xor_si128(data, sig_bytes);
                _mm_testz_si128(neq, sig_mask) != 0
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
    if post_begin < end && !post_begin.is_null() {
        return crate::scanner::scan_single_raw(post_begin, end, sig, cmp_index);
    }

    ConstScanResult::null()
}

fn create_align_mask_16(cmp_index: usize) -> u16 {
    let mut mask: u16 = 0;
    let mut i = cmp_index % 16;
    while i < 16 {
        mask |= 1u16 << i;
        i += 16;
    }
    mask
}
