use std::fs;

use anyhow::Result;
use arg::Args;
use gm_addr_extract_lib::{
    extract_gm_addr,
    patterns::{AdrpAdrpStrStr, AdrpLdrAdrpLdr},
};

mod arg;

fn main() -> Result<()> {
    let Args { il2cpp_so_path } = argh::from_env();
    let lib_data = fs::OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .append(false)
        .open(il2cpp_so_path)?;

    if let Ok(gm_addr_mode1) = extract_gm_addr(&lib_data, AdrpAdrpStrStr) {
        println!("0x{gm_addr_mode1:X}");
        return Ok(());
    }

    eprintln!("Mode 1 failed. falling back to mode 2...");

    if let Ok(gm_addr_mode2) = extract_gm_addr(lib_data, AdrpLdrAdrpLdr) {
        println!("0x{gm_addr_mode2:X}");
    }

    Ok(())
}
