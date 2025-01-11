use anyhow::anyhow;
use disarm64::{
    decoder::{Mnemonic, Operation, LDST_POS, PCRELADDR},
    Opcode,
};
use itertools::Itertools;

#[derive(Debug, Clone, Copy)]
pub struct AdrpAdrpStrStr;

impl super::Pattern for AdrpAdrpStrStr {
    fn try_find_pc_relative_addr(
        &self,
        insns: impl Iterator<Item = Opcode>,
    ) -> anyhow::Result<(u64, usize)> {
        insns
            .tuple_windows::<(_, _, _, _)>()
            .enumerate()
            .filter(|(_idx, (o0, o1, o2, o3))| {
                matches!(
                    (o0.mnemonic, o1.mnemonic, o2.mnemonic, o3.mnemonic),
                    (Mnemonic::adrp, Mnemonic::adrp, Mnemonic::str, Mnemonic::str)
                )
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

                if s0.imm12() != s1.imm12() + 1 {
                    return None;
                }

                Some((idx, (p0, s0)))
            })
            .next()
            .ok_or_else(|| anyhow!("failed to find"))
            .map(|(idx, (p0, s0))| {
                let p_addr = (((p0.immhi() as u64) << 2) | p0.immlo() as u64) << 12;
                let offset = (s0.imm12() * 8) as u64;
                (p_addr + offset, idx)
            })
    }
}
