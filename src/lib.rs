use std::io::{Read, Seek};

use anyhow::anyhow;

use disarm64::decoder_full;
use elf::{endian::LittleEndian, segment::ProgramHeader, ElfStream};

pub mod patterns;

pub fn extract_gm_addr(
    elf_bytes: impl Seek + Read,
    pat: impl patterns::Pattern,
) -> anyhow::Result<u64> {
    let mut lib = ElfStream::<LittleEndian, _>::open_stream(elf_bytes)?;
    let text_section = *lib
        .section_header_by_name(".text")?
        .ok_or_else(|| anyhow!(".text not found"))?;
    let text_addr = text_section.sh_offset as usize;

    let text_section_bytes = lib.section_data(&text_section)?.0;
    let insns = text_section_bytes
        .chunks(4)
        .flat_map(<[u8; 4]>::try_from)
        .map(u32::from_le_bytes)
        .filter_map(decoder_full::decode);

    let (pc_relative_addr, idx) = pat.try_find_pc_relative_addr(insns)?;

    let pc_off_from_0 = (text_addr + idx * 4) as u64;

    let ProgramHeader { p_offset, .. } = lib
        .segments()
        .iter()
        .find(
            |ProgramHeader {
                 // for .text segments, assume filesz == memsz
                 p_offset,
                 p_filesz,
                 ..
             }| { (*p_offset..p_offset + p_filesz).contains(&pc_off_from_0) },
        )
        .ok_or_else(|| anyhow!("failed to find corrosponding segment!"))?;
    let pc = (pc_off_from_0 - p_offset) >> 12 << 12;
    let base_relative_addr = pc_relative_addr + pc;
    Ok(base_relative_addr)
}
