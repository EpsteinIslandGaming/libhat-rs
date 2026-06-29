use core::arch::aarch64::*;

use crate::scanner::{ScanAlignment, ScanContext};
use crate::result::ConstScanResult;

unsafe fn load_sig_128(sig: &[crate::signature::SignatureElement]) -> (uint8x16_t, uint8x16_t) {
    let mut bytes = [0u8; 16];
    let mut mask = [0u8; 16];
    for (i, e) in sig.iter().enumerate().take(16) {
        bytes[i] = e.value();
        mask[i] = e.mask();
    }
    (vld1q_u8(bytes.as_ptr()), vld1q_u8(mask.as_ptr()))
}

unsafe fn align_up_16(ptr: *const u8) -> *const u8 {
    let addr = ptr as usize;
    let rem = addr & 15;
    if rem == 0 { ptr } else { ptr.add(16 - rem) }
}

fn create_align_mask_neon(cmp_index: usize) -> u64 {
    let mut mask: u64 = 0;
    let mut i = cmp_index % 16;
    while i < 16 {
        mask |= 0xFu64 << (i * 4);
        i += 16;
    }
    mask
}

pub(crate) unsafe fn scan_neon(
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

    let first_byte = vdupq_n_u8(sig[cmp_index].value());

    let second_byte = if use_pair {
        vdupq_n_u8(sig[cmp_index + 1].value())
    } else {
        vdupq_n_u8(0)
    };

    let (sig_bytes, sig_mask) = if veccmp {
        load_sig_128(sig)
    } else {
        (vdupq_n_u8(0), vdupq_n_u8(0))
    };

    let vec_start = align_up_16(begin.add(cmp_index)) as *const uint8x16_t;
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
        let data = vld1q_u8(it as *const u8);
        let cmp = vceqq_u8(first_byte, data);

        let narrow = vshrn_n_u16(vreinterpretq_u16_u8(cmp), 4);
        let mut mask: u64 = vget_lane_u64(vreinterpret_u64_u8(narrow), 0);

        if use_pair {
            let cmp2 = vceqq_u8(second_byte, data);
            let narrow2 = vshrn_n_u16(vreinterpretq_u16_u8(cmp2), 4);
            let mask2: u64 = vget_lane_u64(vreinterpret_u64_u8(narrow2), 0);
            mask &= (mask2 >> 4) | (0xFu64 << 60);
        }

        if alignment == ScanAlignment::X16 {
            let align_mask = create_align_mask_neon(cmp_index);
            mask &= align_mask;
        }

        while mask != 0 {
            let offset = mask.trailing_zeros() as usize;
            let i = (it as *const u8).add(offset >> 2).sub(cmp_index);

            let matched = if veccmp {
                let data = vld1q_u8(i);
                let neq = veorq_u8(data, sig_bytes);
                let masked = vandq_u8(neq, sig_mask);
                vmaxvq_u32(vreinterpretq_u32_u8(masked)) == 0
            } else {
                sig.iter().enumerate().all(|(j, e)| e.matches(*i.add(j)))
            };

            if matched {
                return ConstScanResult::new(i);
            }
            mask ^= 0xFu64 << offset;
        }

        it = it.add(1);
    }

    let post_begin = (vec_it_end as *const u8).sub(cmp_index);
    if post_begin < end && !post_begin.is_null() {
        return crate::scanner::scan_single_raw(post_begin, end, sig, cmp_index);
    }

    ConstScanResult::null()
}
