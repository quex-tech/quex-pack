# quex-pack

`quex-pack` is a tool to convert a container image into a VM image suitable to run as a Trust Domain.

It adds a minimal Linux kernel and an initramfs with an `init` program. `init` expects a secret key for the VM to be supplied via `quex-v1-vault`. This key is then provided to the container via an environment variable.

Container workload may be either added to the initramfs, or put to a SquashFS disk image. Integrity of the disk image is ensured via `dm-verity` with root hash baked into the Linux kernel cmdline.

Result is a Unified kernel image and an optional disk image.

## Installing

Clone the repo and run `install.sh`. That will put `quex-pack` into `/usr/local/bin`.

## Updating

Pull latest changes and run `install.sh` again.

## Usage

See `quex-pack --help` for usage tips.
