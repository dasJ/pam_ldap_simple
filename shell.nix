{ pkgs ? import <nixpkgs> {} }: pkgs.mkShell {
  buildInputs = with pkgs; [
    stdenv
    pam
    openldap
  ];

  nativeBuildInputs = with pkgs; [
    cppcheck
    gdb
  ];
}
