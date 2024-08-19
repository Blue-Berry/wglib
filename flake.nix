{
  description = "A library for interfacing with the wireguard kernel module";

  inputs = {
    nixpkgs.url = "github:nix-ocaml/nix-overlays";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs @ {flake-parts, ...}:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin"];

      perSystem = {
        config,
        self',
        inputs',
        pkgs,
        system,
        ...
      }: let
        inherit (pkgs) dockerTools ocamlPackages mkShell;
        inherit (dockerTools) buildImage;
        inherit (ocamlPackages) buildDunePackage;
        name = "wglib";
        version = "0.0.1";
      in {
        devShells = {
          default = mkShell {
            inputsFrom = [self'.packages.default];
            buildInputs = [pkgs.ocamlPackages.utop pkgs.ocamlPackages.ocaml-lsp pkgs.ocamlPackages.ocamlformat pkgs.ocamlPackages.odoc pkgs.ocamlPackages.magic-trace pkgs.clang-tools];
          };
        };

        packages = {
          default = buildDunePackage {
            inherit version;
            pname = name;
            src = ./.;
            buildInputs = with pkgs.ocamlPackages; [
                ctypes
                ctypes-foreign
            ];
          };

          docker = buildImage {
            inherit name;
            tag = version;
            config = {
              Cmd = ["${self'.packages.default}/bin/${name}"];
              Env = [
                "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              ];
            };
          };
        };
      };
    };
}
