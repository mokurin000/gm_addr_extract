use anyhow::anyhow;

use disarm64::{
    decoder::{LDST_POS, Mnemonic, Operation, PCRELADDR},
    decoder_full,
};
use elf::{ElfBytes, endian::LittleEndian};
use itertools::Itertools;

pub fn extract_gm_addr(elf_bytes: &[u8]) -> anyhow::Result<u64> {
    let lib = ElfBytes::<LittleEndian>::minimal_parse(&elf_bytes)?;
    let text_section = lib
        .section_header_by_name(".text")?
        .ok_or_else(|| anyhow!(".text not found"))?;
    let text_addr = text_section.sh_offset as usize;
    let text_addr_end = text_section.sh_size as usize + text_addr;

    let text_section_bytes = &elf_bytes[text_addr..text_addr_end];

    for (idx, (p0, s0)) in text_section_bytes
        .chunks(4)
        .map(<[u8; 4]>::try_from)
        .flatten()
        .map(u32::from_le_bytes)
        .map(decoder_full::decode)
        .flatten()
        .tuple_windows::<(_, _, _, _)>()
        .enumerate()
        .filter(|(_idx, (o0, o1, o2, o3))| {
            match (o0.mnemonic, o1.mnemonic, o2.mnemonic, o3.mnemonic) {
                (Mnemonic::adrp, Mnemonic::adrp, Mnemonic::str, Mnemonic::str) => true,
                _ => false,
            }
        })
        .filter_map(|(idx, (o0, o1, s0, s1))| {
            let (
                Operation::PCRELADDR(PCRELADDR::ADRP_Rd_ADDR_ADRP(p0)),
                Operation::PCRELADDR(PCRELADDR::ADRP_Rd_ADDR_ADRP(p1)),
            ) = (o0.operation, o1.operation)
            else {
                return None;
            };

            if p0.immhi() == p1.immhi() && p0.immlo() == p1.immlo() {
                Some((idx, (p0, p1, s0, s1)))
            } else {
                None
            }
        })
        .filter_map(|(idx, (p0, _, s0, s1))| {
            let (
                Operation::LDST_POS(LDST_POS::STR_Rt_ADDR_UIMM12(s0)),
                Operation::LDST_POS(LDST_POS::STR_Rt_ADDR_UIMM12(s1)),
            ) = (s0.operation, s1.operation)
            else {
                return None;
            };

            if s0.imm12() < s1.imm12() {
                return None;
            }

            if s0.imm12() != s1.imm12() + 1 {
                return None;
            }

            Some((idx, (p0, s0)))
        })
    {
        let p_addr = (((p0.immhi() as u64) << 2) | p0.immlo() as u64) << 12;
        let offset = (s0.imm12() * 8) as u64;
        let pc_off = ((text_addr + idx * 4) >> 12 << 12) as u64;
        let addr = p_addr + offset + pc_off;
        return Ok(addr);
    }

    anyhow::bail!("addr not found")
}
