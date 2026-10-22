{ pkgs, inputs, ... }:

let
  # cargo-fuzz needs nightly; the rest of the build uses stable.
  nightly = (inputs.rust-overlay.lib.mkRustBin { } pkgs).selectLatestNightlyWith (t: t.minimal);
  # +crt-static needs libc.a, but on every link's search path it breaks the dynamic proc-macro
  # links, so add it only to static ones.
  staticLinker = pkgs.writeShellScript "static-glibc-cc" ''
    for a; do
      case $a in -static | -static-pie) set -- "$@" -L${pkgs.glibc.static}/lib; break ;; esac
    done
    exec ${pkgs.clang}/bin/clang --ld-path=${pkgs.llvmPackages.bintools}/bin/ld.lld "$@"
  '';
in
{
  languages.rust = {
    enable = true;
    channel = "stable";
    targets = [ "x86_64-unknown-linux-gnu" "aarch64-unknown-linux-musl" ];
  };

  packages = [
    pkgs.python3 # scripts/gen_*.py
    pkgs.qemu-user # tests on other architectures
    pkgs.cargo-fuzz
  ];

  env.CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = pkgs.lib.mkForce "${staticLinker}";

  scripts.fuzz.exec = ''PATH=${nightly}/bin:$PATH cargo fuzz "$@"'';
  scripts.fuzz.description = "cargo fuzz, run with a nightly toolchain";
}
