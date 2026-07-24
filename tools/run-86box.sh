#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VM_PROFILE=${1:-vm}
VM_PATH="$ROOT/targets/ibm_pc_5150/86box/$VM_PROFILE"
IMAGE="$ROOT/build/ibm_pc_5150/floppy-160k.img"
case "$VM_PROFILE" in
    vm-net-286|vm-net-386|vm-net-ne2k|vm-net-novell-ne2k|vm-net-wd8013ebt|vm-net-ne2kpnp|vm-net-de220p|vm-net-pcnetisa|vm-net-pcnetracal|vm-net-pcnetisaplus|vm-net-ne2kpci|vm-net-pcnetpci|vm-net-pcnetfast|vm-net-pcnetvlb|vm-net-dec21040|vm-net-dec21140|vm-net-dec21140vpc|vm-net-dec21143|vm-net-rtl8139)
        IMAGE="$ROOT/build/ibm_pc_5150/floppy-360k.img"
        ;;
    vm-net-pcnetfast-onboard|vm-net-ethernextmc|vm-net-wd8003eta|vm-net-wd8003ea|vm-net-wd8013epa)
        IMAGE="$ROOT/build/ibm_pc_5150/floppy-1440k.img"
        ;;
esac

if command -v 86Box >/dev/null 2>&1; then
  EMULATOR=86Box
elif [ -x /Applications/86Box.app/Contents/MacOS/86Box ]; then
  EMULATOR=/Applications/86Box.app/Contents/MacOS/86Box
else
  echo "86Box was not found. Install 86Box, then run this script again." >&2
  exit 1
fi

if [ ! -d "$VM_PATH" ]; then
    echo "Missing 86Box VM path: $VM_PATH" >&2
    echo "Available profiles:" >&2
    find "$ROOT/targets/ibm_pc_5150/86box" -mindepth 1 -maxdepth 1 -type d -name 'vm*' -exec basename {} \; | sort >&2
    exit 1
fi

make -C "$ROOT"
exec "$EMULATOR" --vmpath "$VM_PATH" --image "A:$IMAGE"
