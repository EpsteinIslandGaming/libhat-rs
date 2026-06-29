use criterion::{black_box, criterion_group, criterion_main, Criterion};

use hat::signature::parse_signature;
use hat::scanner::{find_pattern, find_all_pattern, ScanAlignment, ScanHint};

fn bench_find_pattern_16(c: &mut Criterion) {
    let sig = parse_signature("48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ?? 49").unwrap();
    let mut data = vec![0x00u8; 256 * 1024 * 1024];
    data[4_000_000..4_000_000 + 16].copy_from_slice(&[
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89,
        0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC,
        0x00, 0x49,
    ]);

    c.bench_function("find_pattern_256MB_X1", |b| {
        b.iter(|| {
            let result = find_pattern(
                black_box(data.as_ptr()),
                black_box(unsafe { data.as_ptr().add(data.len()) }),
                black_box(&sig),
                black_box(ScanAlignment::X1),
                black_box(ScanHint::NONE),
            );
            black_box(result);
        })
    });

    c.bench_function("find_pattern_256MB_X16", |b| {
        b.iter(|| {
            let result = find_pattern(
                black_box(data.as_ptr()),
                black_box(unsafe { data.as_ptr().add(data.len()) }),
                black_box(&sig),
                black_box(ScanAlignment::X16),
                black_box(ScanHint::NONE),
            );
            black_box(result);
        })
    });
}

fn bench_find_pattern_short(c: &mut Criterion) {
    let sig = parse_signature("E8 ? ? ? ?").unwrap();
    let mut data = vec![0x00u8; 64 * 1024 * 1024];
    data[8_000_000..8_000_000 + 5].copy_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);

    c.bench_function("find_pattern_64MB_5byte", |b| {
        b.iter(|| {
            let result = find_pattern(
                black_box(data.as_ptr()),
                black_box(unsafe { data.as_ptr().add(data.len()) }),
                black_box(&sig),
                black_box(ScanAlignment::X1),
                black_box(ScanHint::NONE),
            );
            black_box(result);
        })
    });
}

fn bench_find_all_pattern(c: &mut Criterion) {
    let sig = parse_signature("00 00").unwrap();
    let data = vec![0x00u8; 1024];

    c.bench_function("find_all_pattern_1KB", |b| {
        b.iter(|| {
            let results = find_all_pattern(
                black_box(data.as_ptr()),
                black_box(unsafe { data.as_ptr().add(data.len()) }),
                black_box(&sig),
                black_box(ScanAlignment::X1),
                black_box(ScanHint::NONE),
            );
            black_box(results.len());
        })
    });
}

fn bench_not_found(c: &mut Criterion) {
    let sig = parse_signature("FF FF FF FF FF FF FF FF").unwrap();
    let data = vec![0x00u8; 64 * 1024 * 1024];

    c.bench_function("find_pattern_64MB_not_found", |b| {
        b.iter(|| {
            let result = find_pattern(
                black_box(data.as_ptr()),
                black_box(unsafe { data.as_ptr().add(data.len()) }),
                black_box(&sig),
                black_box(ScanAlignment::X1),
                black_box(ScanHint::NONE),
            );
            black_box(result);
        })
    });
}

criterion_group!(
    benches,
    bench_find_pattern_16,
    bench_find_pattern_short,
    bench_find_all_pattern,
    bench_not_found,
);
criterion_main!(benches);
