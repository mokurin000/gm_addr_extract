use anyhow::anyhow;
use disarm64::{
    decoder::{Operation, LDST_POS, PCRELADDR},
    decoder_full::Mnemonic,
};
use itertools::Itertools;

use super::Pattern;

pub struct AdrpLdrAdrpLdr;

impl Pattern for AdrpLdrAdrpLdr {
    fn try_find_pc_relative_addr(
        &self,
        insns: impl Iterator<Item = disarm64::Opcode>,
    ) -> anyhow::Result<(u64, usize)> {
        insns
            .tuple_windows::<(_, _, _, _)>()
            .enumerate()
            .filter(|(_idx, (o0, o1, o2, o3))| {
                matches!(
                    (o0.mnemonic, o1.mnemonic, o2.mnemonic, o3.mnemonic),
                    (Mnemonic::adrp, Mnemonic::ldr, Mnemonic::adrp, Mnemonic::ldr)
                )
            })
            .filter_map(|(idx, (a1, l1, a2, l2))| {
                let (
                    Operation::PCRELADDR(PCRELADDR::ADRP_Rd_ADDR_ADRP(p0)),
                    Operation::PCRELADDR(PCRELADDR::ADRP_Rd_ADDR_ADRP(p1)),
                    Operation::LDST_POS(LDST_POS::LDR_Rt_ADDR_UIMM12(s0)),
                    Operation::LDST_POS(LDST_POS::LDR_Rt_ADDR_UIMM12(s1)),
                ) = (a1.operation, a2.operation, l1.operation, l2.operation)
                else {
                    return None;
                };

                if p0.immhi() != p1.immhi() || p0.immlo() != p1.immlo() {
                    return None;
                }

                if s0.imm12() != s1.imm12() + 1 {
                    return None;
                }

                Some((idx, (p0, s0, p1, s1)))
            })
            .next()
            .ok_or_else(|| anyhow!("failed to find instruction!"))
            .map(|(idx, (a0, _, _, l1))| {
                let adrp_addr = (((a0.immhi() as u64) << 2) | a0.immlo() as u64) << 12;
                let ldr_offset = (l1.imm12() as u64) << 3;

                (adrp_addr + ldr_offset, idx)
            })
    }
}
