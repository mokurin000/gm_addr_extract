use disarm64::Opcode;

mod adrp_adrp_str_str;
pub use adrp_adrp_str_str::AdrpAdrpStrStr;
mod adrp_ldr_adrp_ldr;
pub use adrp_ldr_adrp_ldr::AdrpLdrAdrpLdr;

pub trait Pattern {
    fn try_find_pc_relative_addr(
        &self,
        insns: impl Iterator<Item = Opcode>,
    ) -> anyhow::Result<(u64, usize)>;
}
