use std::fmt;
use std::mem;

#[derive(Clone, Copy)]
pub struct ScanResult {
    ptr: *mut u8,
}

unsafe impl Send for ScanResult {}

#[derive(Clone, Copy)]
pub struct ConstScanResult {
    ptr: *const u8,
}

unsafe impl Send for ConstScanResult {}

impl ScanResult {
    pub fn new(ptr: *mut u8) -> Self {
        Self { ptr }
    }

    pub fn null() -> Self {
        Self { ptr: std::ptr::null_mut() }
    }

    pub fn has_result(&self) -> bool {
        !self.ptr.is_null()
    }

    pub fn get(&self) -> *mut u8 {
        self.ptr
    }

    pub fn read<Int: Copy>(&self, offset: usize) -> Int {
        assert!(!self.ptr.is_null());
        unsafe { std::ptr::read_unaligned(self.ptr.add(offset) as *const Int) }
    }

    pub fn index<Int: Copy>(&self, offset: usize, _elem_size: usize) -> usize {
        let val: Int = self.read(offset);
        let val_u64 = unsafe {
            let bytes = std::slice::from_raw_parts(&val as *const Int as *const u8, mem::size_of::<Int>());
            match mem::size_of::<Int>() {
                1 => bytes[0] as u64,
                2 => u16::from_ne_bytes(bytes.try_into().unwrap()) as u64,
                4 => u32::from_ne_bytes(bytes.try_into().unwrap()) as u64,
                8 => u64::from_ne_bytes(bytes.try_into().unwrap()),
                _ => unreachable!(),
            }
        };
        (val_u64 as usize) / _elem_size
    }

    pub fn rel(&self, offset: usize, remaining: usize) -> *mut u8 {
        if !self.has_result() {
            return std::ptr::null_mut();
        }
        let rel: i32 = self.read(offset);
        unsafe {
            self.ptr
                .add(offset)
                .add(rel as usize)
                .add(4)
                .add(remaining)
        }
    }
}

impl ConstScanResult {
    pub fn new(ptr: *const u8) -> Self {
        Self { ptr }
    }

    pub fn null() -> Self {
        Self { ptr: std::ptr::null() }
    }

    pub fn has_result(&self) -> bool {
        !self.ptr.is_null()
    }

    pub fn get(&self) -> *const u8 {
        self.ptr
    }

    pub fn read<Int: Copy>(&self, offset: usize) -> Int {
        assert!(!self.ptr.is_null());
        unsafe { std::ptr::read_unaligned(self.ptr.add(offset) as *const Int) }
    }

    pub fn index<Int: Copy>(&self, offset: usize, _elem_size: usize) -> usize {
        let val: Int = self.read(offset);
        let val_u64 = unsafe {
            let bytes = std::slice::from_raw_parts(&val as *const Int as *const u8, mem::size_of::<Int>());
            match mem::size_of::<Int>() {
                1 => bytes[0] as u64,
                2 => u16::from_ne_bytes(bytes.try_into().unwrap()) as u64,
                4 => u32::from_ne_bytes(bytes.try_into().unwrap()) as u64,
                8 => u64::from_ne_bytes(bytes.try_into().unwrap()),
                _ => unreachable!(),
            }
        };
        (val_u64 as usize) / _elem_size
    }

    pub fn rel(&self, offset: usize, remaining: usize) -> *const u8 {
        if !self.has_result() {
            return std::ptr::null();
        }
        let rel: i32 = self.read(offset);
        unsafe {
            self.ptr
                .add(offset)
                .add(rel as usize)
                .add(4)
                .add(remaining)
        }
    }
}

impl From<ScanResult> for ConstScanResult {
    fn from(result: ScanResult) -> Self {
        ConstScanResult { ptr: result.ptr as *const u8 }
    }
}

impl PartialEq for ScanResult {
    fn eq(&self, other: &Self) -> bool {
        self.ptr == other.ptr
    }
}

impl PartialEq for ConstScanResult {
    fn eq(&self, other: &Self) -> bool {
        self.ptr == other.ptr
    }
}

impl fmt::Debug for ScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScanResult({:?})", self.ptr)
    }
}

impl fmt::Debug for ConstScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConstScanResult({:?})", self.ptr)
    }
}
