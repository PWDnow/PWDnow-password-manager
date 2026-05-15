# Host Hardening Guide

For maximum security, the following host-level hardening measures are strongly recommended:

## Kernel Parameters
Apply these settings via /etc/sysctl.d/99-vault.conf:

kernel.yama.ptrace_scope = 2
kernel.kptr_restrict = 2
vm.swappiness = 0

## Swap
Disable swap completely to ensure mlock() guarantees are never bypassed by the kernel's OOM killer or hibernation mechanisms:
sudo swapoff -a
Remove any swap entries from /etc/fstab.

## Storage and Firmware
- **Full Disk Encryption (FDE)**: Use LUKS for the root filesystem.
- **BIOS/UEFI Password**: Set a strong firmware password and disable boot from external media.
