{
  lib,
  pkgs,
  nixpkgs,
  system,
  target,
  fenix,
  buildDir,
  testOpt,
  rootfsType ? "vfat",
  diskPath,
  partitionType ? "mbr",
  baseImage ? null,
}:

let
  image = import ./rootfs-tar.nix {
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

  # parted 使用 msdos 而不是 mbr
  partedLabel = if partitionType == "mbr" then "msdos" else partitionType;

  # 根据文件系统类型生成 mkfs 命令
  mkfsCommand =
    if rootfsType == "vfat" then
      ''sudo mkfs.vfat "''${LOOP_DEV}p1"''
    else if rootfsType == "ext4" then
      ''sudo mkfs.ext4 -F "''${LOOP_DEV}p1"''
    else
      ''sudo mkfs -t ${rootfsType} "''${LOOP_DEV}p1"'';

  # vfat 特殊处理脚本片段
  vfatProcessing = ''
    echo "  Processing rootfs for vfat (excluding /nix/store, dereferencing symlinks)..."

    EXTRACT_DIR=$(mktemp -d)
    FILTERED_TAR="${buildDir}/rootfs-filtered.tar"

    # 解压原始 tar，排除 /nix/store
    echo "    Extracting and not filtering..."
    chmod +w -R "$TEMP_DIR" "$EXTRACT_DIR"
    fakeroot tar --owner=0 --group=0 --numeric-owner --exclude='proc' --exclude='dev' \
        --exclude='sys' -xf "$OUTPUT_TAR" -C "$EXTRACT_DIR"

    # 重新打包，解引用符号链接和硬链接
    echo "    Re-packing with dereferenced links..."
    fakeroot tar --owner=0 --group=0 --numeric-owner --dereference --hard-dereference -cf "$FILTERED_TAR" -C "$EXTRACT_DIR" .

    FILTERED_SIZE=$(du -h "$FILTERED_TAR" | cut -f1)
    echo "  ✓ Re-packed rootfs.tar created ($FILTERED_SIZE)"

    FINAL_TAR="$FILTERED_TAR"
  '';

  # 非 vfat 不需要特殊处理
  nonVfatProcessing = ''
    FINAL_TAR="$OUTPUT_TAR"
  '';

  # 根据 rootfsType 选择处理逻辑
  rootfsProcessing = if rootfsType == "vfat" then vfatProcessing else nonVfatProcessing;

  # guestfish 写盘逻辑
  guestfishWrite = ''
    echo "  Using guestfish (unprivileged mode)..."
    export LIBGUESTFS_CACHEDIR=/tmp
    export LIBGUESTFS_BACKEND=direct

    # 使用 guestfish 创建分区并注入 tar
    echo "  Initializing disk and copying rootfs..."
    guestfish -a "$TEMP_IMG" <<EOF
      run
      part-init /dev/sda ${partitionType}
      part-add /dev/sda primary 2048 -2048
      mkfs ${rootfsType} /dev/sda1
      mount /dev/sda1 /
      tar-in $FINAL_TAR /
      chmod 0755 /
      umount /
      sync
      shutdown
    EOF
  '';

  # loop 设备写盘逻辑
  loopWrite = ''
    echo "  Using loop device (privileged mode, faster)..."

    # 使用 parted 创建分区表和分区
    echo "    Creating partition table..."
    parted -s "$TEMP_IMG" mklabel ${partedLabel}
    parted -s "$TEMP_IMG" mkpart primary ${rootfsType} 1MiB 100%

    # 设置 loop 设备
    echo "    Setting up loop device..."
    LOOP_DEV=$(sudo losetup --find --show --partscan "$TEMP_IMG")
    echo "    Loop device: $LOOP_DEV"

    # 确保清理 loop 设备
    # shellcheck disable=SC2317,SC2329
    cleanup_loop() {
      echo "    Cleaning up loop device..."
      sudo umount "''${LOOP_DEV}p1" 2>/dev/null || true
      sudo losetup -d "$LOOP_DEV" 2>/dev/null || true
    }
    trap 'cleanup_loop; chmod +w -R "$TEMP_DIR" 2>/dev/null && rm -rf "$TEMP_DIR"; [ -n "$EXTRACT_DIR" ] && chmod +w -R "$EXTRACT_DIR" 2>/dev/null && rm -rf "$EXTRACT_DIR"' EXIT

    # 等待分区设备出现
    echo "    Waiting for partition device..."
    for _ in $(seq 1 10); do
      if [ -b "''${LOOP_DEV}p1" ]; then
        break
      fi
      sleep 0.1
    done

    if [ ! -b "''${LOOP_DEV}p1" ]; then
      echo "Error: Partition device ''${LOOP_DEV}p1 not found"
      exit 1
    fi

    # 格式化分区
    echo "    Formatting partition as ${rootfsType}..."
    ${mkfsCommand}

    # 挂载分区
    MOUNT_DIR=$(mktemp -d)
    echo "    Mounting partition to $MOUNT_DIR..."
    sudo mount "''${LOOP_DEV}p1" "$MOUNT_DIR"

    # 更新 trap 以包含 MOUNT_DIR
    # shellcheck disable=SC2317,SC2329
    cleanup_loop() {
      echo "    Cleaning up..."
      sudo umount "$MOUNT_DIR" 2>/dev/null || true
      sudo losetup -d "$LOOP_DEV" 2>/dev/null || true
      rm -rf "$MOUNT_DIR" 2>/dev/null || true
    }
    trap 'cleanup_loop; chmod +w -R "$TEMP_DIR" 2>/dev/null && rm -rf "$TEMP_DIR"; [ -n "$EXTRACT_DIR" ] && chmod +w -R "$EXTRACT_DIR" 2>/dev/null && rm -rf "$EXTRACT_DIR"' EXIT

    # 解压 tar 到分区
    echo "    Extracting rootfs to partition..."
    sudo tar -xf "$FINAL_TAR" -C "$MOUNT_DIR"
    sudo chmod 0755 "$MOUNT_DIR"

    # 同步并卸载
    echo "    Syncing and unmounting..."
    sync
    sudo umount "$MOUNT_DIR"
    sudo losetup -d "$LOOP_DEV"
    rm -rf "$MOUNT_DIR"

    # 重置 trap
    trap 'chmod +w -R "$TEMP_DIR" 2>/dev/null && rm -rf "$TEMP_DIR"; [ -n "$EXTRACT_DIR" ] && chmod +w -R "$EXTRACT_DIR" 2>/dev/null && rm -rf "$EXTRACT_DIR"' EXIT
  '';

  # 构建脚本 - 在bin/目录下构建
  buildScript = pkgs.writeShellApplication {
    name = "dragonos-rootfs";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.gnutar
      pkgs.jq
      pkgs.rsync
      pkgs.libguestfs-with-appliance
      pkgs.findutils
      pkgs.parted
      pkgs.dosfstools
      pkgs.e2fsprogs
      pkgs.util-linux
    ];
    text = ''
      set -euo pipefail

      # 记录起始目录
      START_DIR="''$(pwd)"

      # Ensure build directory exists
      mkdir -p "${buildDir}"

      OUTPUT_TAR="${buildDir}/rootfs.tar"

      echo "==> Generating rootfs"

      # 创建临时目录
      TEMP_DIR=$(mktemp -d)
      EXTRACT_DIR=""  # 初始化为空，vfat 处理时会赋值
      trap 'chmod +w -R "$TEMP_DIR" 2>/dev/null && rm -rf "$TEMP_DIR"; [ -n "$EXTRACT_DIR" ] && chmod +w -R "$EXTRACT_DIR" 2>/dev/null && rm -rf "$EXTRACT_DIR"' EXIT

      # 提取 layer.tar (rootfs)
      echo "  Extracting rootfs layer..."
      cd "$TEMP_DIR"
      tar -xzf ${image}

    ${if baseImage != null then ''
      # 有 base image 时：按 manifest.json 中 Layers 顺序合并所有层
      # 策略：先解压 base 层保留符号链接结构，再用 rsync --ignore-existing 叠加增量层
      # 这样 Ubuntu 的 passwd/group/shadow 等文件被保留，DragonOS 只添加新增文件
      echo "  Merging layers from base image + DragonOS apps..."
      LAYERS=$(jq -r '.[].Layers[]' manifest.json)
      if [ -z "$LAYERS" ]; then
        echo "Error: no layers found in manifest.json"
        exit 1
      fi

      MERGE_DIR=$(mktemp -d)
      LAYER_IDX=0
      for layer in $LAYERS; do
        echo "    Applying layer: $layer"
        if [ "$LAYER_IDX" -eq 0 ]; then
          # 第一层（base image）：直接解压到合并目录，保留符号链接
          tar -xf "$layer" -C "$MERGE_DIR"
        else
          # 增量层：解压到临时目录，用 rsync --ignore-existing 叠加
          # --ignore-existing 保留 base 层已有的文件（如 Ubuntu 的 passwd/group），
          # 只添加 base 中不存在的新文件（如 DragonOS 的 busybox、测试程序等）
          LAYER_DIR=$(mktemp -d)
          tar -xf "$layer" -C "$LAYER_DIR" --exclude='/nix' --exclude='./nix' || true
          rm -rf "$LAYER_DIR/nix" 2>/dev/null || true
          rsync -a --ignore-existing "$LAYER_DIR"/ "$MERGE_DIR"/ || true
          chmod -R +w "$LAYER_DIR" 2>/dev/null || true
          rm -rf "$LAYER_DIR" 2>/dev/null || true
        fi
        LAYER_IDX=$((LAYER_IDX + 1))
      done

      # 清理可能残留的 nix 目录
      rm -rf "$MERGE_DIR/nix" 2>/dev/null || true

      # 输出到 MERGE_DIR 外面，避免 bin -> usr/bin 符号链接导致路径冲突
      cd "$START_DIR"
      ROOTFS_TMP=$(mktemp -u --tmpdir=. rootfs-XXXXXX.tar)
      tar -cf "$ROOTFS_TMP" -C "$MERGE_DIR" .
      mv "$ROOTFS_TMP" "$OUTPUT_TAR"
      chmod -R +w "$MERGE_DIR" 2>/dev/null || true
      rm -rf "$MERGE_DIR"
    '' else ''
      # 无 base image 时：单层，直接取 layer.tar
      LAYER_TAR=$(find . -name "layer.tar" | head -1)
      if [ -z "$LAYER_TAR" ]; then
        echo "Error: layer.tar not found in docker image"
        exit 1
      fi

      cp "$LAYER_TAR" "$OLDPWD/$OUTPUT_TAR"
      cd "$OLDPWD"
    ''}

      chmod +w "$OUTPUT_TAR"

      TAR_SIZE=$(du -h "$OUTPUT_TAR" | cut -f1)
      echo "  ✓ rootfs.tar created ($TAR_SIZE)"

      # 根据文件系统类型处理 rootfs（Nix 编译时决定）
      ${rootfsProcessing}

      echo "==> Building disk image at ${diskPath}"

      # 创建磁盘镜像并初始化文件系统
      echo "  Creating disk image..."
      TEMP_IMG="${diskPath}.tmp"

      # 计算所需磁盘大小：tar包大小 + 1G 缓冲空间
      TAR_SIZE_KB=$(du -k "$FINAL_TAR" | cut -f1)
      DISK_SIZE_KB=$(( TAR_SIZE_KB + 1024 * 1024 ))
      truncate -s "''${DISK_SIZE_KB}K" "$TEMP_IMG"

      # 检查是否使用非特权构建模式（guestfish）
      if [ "''${DRAGONOS_UNPRIVILEGED_BUILD:-0}" = "1" ]; then
        ${guestfishWrite}
      else
        ${loopWrite}
      fi

      mv -f "$TEMP_IMG" "${diskPath}"

      IMG_SIZE=$(du -h "${diskPath}" | cut -f1)
      echo "  ✓ disk image created ($IMG_SIZE)"

      echo "==> Build complete!"
      echo "    Rootfs tar: $OUTPUT_TAR"
      echo "    Disk image: ${diskPath}"
    '';
  };

in
buildScript
