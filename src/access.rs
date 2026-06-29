pub unsafe fn member_at<'a, T, Base>(ptr: *const Base, offset: usize) -> &'a T {
    let addr = ptr as usize + offset;
    &*(addr as *const T)
}

pub unsafe fn member_at_mut<'a, T, Base>(ptr: *mut Base, offset: usize) -> &'a mut T {
    let addr = ptr as usize + offset;
    &mut *(addr as *mut T)
}
