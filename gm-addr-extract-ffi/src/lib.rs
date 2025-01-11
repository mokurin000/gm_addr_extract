use std::{
    fs::{self, File},
    num::NonZero,
    path::Path,
    slice,
};

use gm_addr_extract_lib::patterns::AdrpAdrpStrStr;

#[no_mangle]
extern "C" fn rva_from_current_process() -> u64 {
    _rva_from_current_process().map(NonZero::into).unwrap_or(0)
}

#[no_mangle]
/*
SAFETY: you must pass null-terminated, UTF-8 encoded string.

You must deallocate it yourself.

`len` means bytes of the string, without the trailing null.
*/
unsafe extern "C" fn rva_from_path(file_path: *const u8, len: usize) -> u64 {
    let utf8_slice = unsafe { slice::from_raw_parts(file_path as _, len) };
    let path = String::from_utf8_lossy(utf8_slice);

    _rva_from_path(path.as_ref())
        .map(NonZero::into)
        .unwrap_or(0)
}

fn _rva_from_current_process() -> Option<NonZero<u64>> {
    let maps = fs::read_to_string("/proc/self/maps").ok()?;
    let path = maps
        .split("\n")
        .filter_map(|s| s.split_ascii_whitespace().last())
        .filter(|s| s.starts_with("/"))
        .filter(|s| s.ends_with("libil2cpp.so"))
        .next()?;
    _rva_from_path(path)
}

fn _rva_from_path(path: impl AsRef<Path>) -> Option<NonZero<u64>> {
    let file = File::open(path).ok()?;

    let rva = gm_addr_extract_lib::extract_gm_addr(file, AdrpAdrpStrStr).ok()?;

    NonZero::new(rva)
}
