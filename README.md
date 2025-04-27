# waoo

a simple eBPF program writen by rust/aya 

```
A simple eBPF program

Usage: waoo <COMMAND>

Commands:
  opensnoop  Tracing open syscalls
  killsnoop  Tracing kill syscalls
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

打印服务器发送kill命令的服务。
```
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- killsnoop
Tracing kill syscalls... Hit Ctrl-C to end.
KILLER COMM             SIG  PID RET
Waiting for Ctrl-C...
531700 code    0 203 0
  1204 background moni    0 1403 0
  1204 background moni    0   0 0
```

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)
1. `cargo install --git https://github.com/aya-rs/aya -- aya-tool`

## Build & Run
```shell
aya-tool generate sock > waoo-ebpf/src/sock_binding.rs
```

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package waoo --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/waoo` can be
copied to a Linux server or VM and run there.
