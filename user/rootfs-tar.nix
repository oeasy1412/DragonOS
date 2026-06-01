{
  lib,
  pkgs,
  nixpkgs,
  system,
  target,
  fenix,
  testOpt,
  baseImage ? null,
}:

# 产物是一个可以生成 rootfs.tar 的脚本
let
  apps = import ./apps {
    inherit
      lib
      pkgs
      nixpkgs
      system
      target
      fenix
      testOpt
      baseImage
      ;
  };

  sys-config =
    pkgs.runCommand "sysconfig"
      {
        src = ./sysconfig;
      }
      ''
        mkdir -p $out $out/root
        cp -r $src/* $out/
      '';

  # 使用 buildImage 创建 Docker 镜像
  # 当 baseImage 非空时，基于该镜像叠加（如 ubuntu:24.04）
  # 直接返回 dockerImage，解压逻辑在 default.nix 中处理
  dockerImage = pkgs.dockerTools.buildImage ({
    name = if baseImage != null then "ubuntu-rootfs" else "busybox-rootfs";
    copyToRoot = [
      sys-config
    ]
    ++ apps;
    keepContentsDirlinks = false;
  } // lib.optionalAttrs (baseImage != null) {
    fromImage = baseImage;
  });

in
dockerImage
