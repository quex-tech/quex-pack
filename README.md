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

```
quex-pack [OPTIONS] SOURCE_IMAGE

Examples:
  quex-pack -o myuki.efi docker-daemon:myimage:mytag

  quex-pack --workload-destination disk -o myuki.efi --output-disk mydisk.img docker-daemon:myimage:mytag

Build a minimalist VM using SOURCE_IMAGE as the workload container.

SOURCE_IMAGE is in transport:details format.
Supported transports: dir, docker, docker-archive, docker-daemon, oci, oci-archive.
See containers-transports(5) (https://github.com/containers/image/blob/main/docs/containers-transports.5.md) for details.

Options:
  -h, --help                  display this help text
  --workload-destination MODE  where to put the workload container: initramfs | disk (default: initramfs)
                                initramfs: container is unpacked into /opt/bundle of initramfs
                                disk: container is saved as a separate .img file and mounted from /dev/vda using dm-verity
  -o, --output PATH           save resulting EFI file to PATH (default: ukernel.efi)
  --output-rootfs PATH        save initramfs to PATH (default: not saved)
  --output-kernel PATH        save Linux kernel to PATH (default: not saved)
  --kernel-cmdline CMD        override kernel command-line parameters (default: console=ttynull or console=ttyS0 if --debug specified)
  --init-args CMD             add extra arguments to init
  --key-request-mask HEX      use HEX as the mask over TD Report for secret key derivation (default: 04030000c70000)
  --vault-mrenclave HEX       override Quex Vault enclave identity
  --builder-image IMAGE       use Docker IMAGE as UKI builder image
  --debug                     use non-minimal Linux kernel build to allow debug output to the console
```

## License

This project is licensed under the [Apache License 2.0](LICENSE).

See the [NOTICE](NOTICE) file for additional copyright and license information.
