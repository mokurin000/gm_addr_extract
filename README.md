# gm-addr-extract

Extract relative GlobalMetadata address for ARM64 ELF `libil2cpp.so`.

On Windows 11 running on `i7-12700H` and `Predator SSD GM7000 2TB`, it could process in 20ms.

```bash
hyperfine.exe --warmup 10 "gm-addr-extract.exe data/com.PigeonGames.Phigros/lib/libil2cpp.so"
```

```text
Benchmark 1: gm-addr-extract.exe data/com.PigeonGames.Phigros/lib/libil2cpp.so
  Time (mean ± σ):      19.5 ms ±   1.5 ms    [User: 0.9 ms, System: 1.2 ms]
  Range (min … max):    16.9 ms …  24.9 ms    116 runs
```

## Targetting Android

For example, to build `gm-addr-extract-ffi` for android using NDK from environment:

```bash
cargo ndk -t arm64-v8a build --release --package gm-addr-extract-ffi -Z build-std=panic_abort,std
```

## Limitatin

- `libil2cpp.so` must be unencrypted.
- Current pattern may find wrong result.
- It depends on optimization level.

## Tested

- Phigros 1.6+ (versions below does not encrypt their global-metadata, the extraction will work too though)
- Among Us
