# nel_os

## Required Tools

- rustup
- cargo
- qemu-system-x86_64

## Build Requirements

```sh
rustup default nightly
rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu
rustup component add llvm-tools-preview
cargo install bootimage
```

## Running

```sh
cargo run --release
```
