#!/bin/bash

# Colors for output
RED='\033[31m'
GREEN='\033[32m'
NC='\033[0m'

# Function to print in color
make_red() { echo -e "${RED}$1${NC}"; }
make_green() { echo -e "${GREEN}$1${NC}"; }

# Function to check mount status
check_mount_status() {
    local mount_point="$1"
    if mountpoint -q "$mount_point"; then
        make_green "$mount_point is mounted! 🎉"
        return 0
    else
        make_red "$mount_point is not mounted. 😞"
        return 1
    fi
}

# Function to mount VHD/VHDX with unknown starting sector
mount_vhd() {
    local image_path="$1"
    local mount_point="$2"
    local output_csv="$3"
    local filesystem="$4"
    local check_status_only="$5"
    local retries=5
    local sleep_time=2
    local nbd_device="/dev/nbd0"

    # Handle status check
    if [ "$check_status_only" = "true" ]; then
        check_mount_status "$mount_point"
        return $?
    fi

    # Validate inputs
    if [ -z "$image_path" ]; then
        make_red "Oops, need an image path (-i)! Try './mount_vhd.sh -i image.vhd [-m /mnt/custom] [-f ntfs|ext4] [-o output.csv] [-s]' 😅"
        return 1
    fi
    if [ ! -f "$image_path" ]; then
        make_red "Hmm, $image_path doesn't exist. Check the path or VHD file? 🤔"
        return 1
    fi
    if [ -n "$filesystem" ] && [[ "$filesystem" != "ntfs" && "$filesystem" != "ext4" ]]; then
        make_red "Invalid filesystem '$filesystem'. Use 'ntfs' or 'ext4'. 😕"
        return 1
    fi
    # Default to ntfs if not specified
    [ -z "$filesystem" ] && filesystem="ntfs"

    # Initialize CSV if specified
    if [ -n "$output_csv" ] && [ ! -e "$output_csv" ]; then
        echo "MountPoint,StartingSector,ByteOffset,Filesystem,PartitionSize,Success" > "$output_csv"
    fi

    # Ensure mount point exists
    mkdir -p "$mount_point" || {
        make_red "Failed to create $mount_point. Permissions issue? 😕"
        return 1
    }

    # Check for fdisk
    if ! command -v fdisk >/dev/null 2>&1; then
        make_red "fdisk not found. Install it (e.g., 'sudo apt install fdisk') for partition size detection! 😞"
    fi

    # Load NBD module
    if ! modprobe nbd; then
        make_red "Failed to load NBD module. Is it installed? 😞"
        return 1
    fi
    make_green "NBD module loaded! 🚀"

    # Attach VHD to NBD device
    if ! qemu-nbd -r -c "$nbd_device" "$image_path"; then
        make_red "Failed