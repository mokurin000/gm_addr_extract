use std::fs;

use anyhow::Result;
use arg::Args;
use gm_addr_extract::extract_gm_addr;

mod arg;

fn main() -> Result<()> {
    let Args { il2cpp_so_path } = argh::from_env();
    let lib_data = fs::OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .append(false)
        .open(il2cpp_so_path)?;

    let gm_addr = extract_gm_addr(lib_data)?;
    println!("0x{gm_addr:X}");

    Ok(())
}
