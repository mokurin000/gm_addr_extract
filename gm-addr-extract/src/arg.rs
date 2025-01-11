use std::path::PathBuf;

use argh::FromArgs;

#[derive(Clone, Debug, FromArgs)]
#[argh(description = "Global-Metadata address extractor.")]
pub struct Args {
    #[argh(positional, description = "path of unencrypted ARM64 libil2cpp.so")]
    pub il2cpp_so_path: PathBuf,
}
