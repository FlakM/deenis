{
  description = "A simple devshell";

  # Flake inputs
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  # Outputs of our flake
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in {
        devShell = pkgs.mkShell {
          LIBCLANG_PATH = "${ pkgs.llvmPackages.libclang.lib }/lib";
#          C_PATH = "${ pkgs.linuxPackages.kernel.dev }/";
          CPATH= "${pkgs.glibc_multi.dev}/include:$CPATH";
#          KERNEL_HEADERS="${pkgs.linuxPackages.kernel.dev}/lib/modules/${pkgs.linuxPackages.kernel.version}/build/include";

          buildInputs = with pkgs; [
            clang
            glibc_multi
            glibc_multi.dev
            linuxPackages.kernel.dev
            llvm
            pkg-config
            libelf
          ];

          nativeBuildInputs = with pkgs; [ pkg-config clang stdenv.cc.libc clang glibc ];

        };
      });
}
