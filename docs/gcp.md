# Running a TD on Google Cloud

Google Compute Engine (GCE) runs Intel TDX Trust Domains as Confidential VMs on C3 machine types. There is no direct kernel boot as with libvirt: the VM boots a disk through UEFI. The scripts in `scripts/` wrap a quex-pack UKI into a minimal GPT disk, import it as a GCE image and start a Confidential VM from it.

## Differences from the libvirt flow

- **Builder image.** GCE C3 networking is gVNIC with DHCP. The builder on this branch enables `CONFIG_GVE` and `CONFIG_IP_PNP_DHCP` in the kernel, and the cmdline carries `ip=dhcp` instead of a static address. A UKI built with the main-branch builder boots but has no network.
- **Workload placement.** Only `--workload-destination initramfs` is supported: the container is embedded in the UKI and there is no separate dm-verity disk.
- **Event log.** `/sys/firmware` is not masked inside the container, so the workload can read the CC event log (ACPI CCEL) and serve it to verifiers.
- **Measurement.** GCE firmware records the UKI as the boot-application event (Authenticode SHA-384) in RTMR[1]. Verification compares a locally rebuilt UKI against that event in the CC event log rather than precomputing RTMRs from an `OVMF.fd`.
- **Key delivery.** Unchanged: after boot `init` listens on port 24516 until `quex-v1-vault` delivers the TD key. The vault runs on any SGX machine of yours and reaches the TD over its external IP.

## Prerequisites

- quex-pack from this branch, installed with `./install.sh`.
- Builder image `quex213/pack:0.0.11-gcp`. If it is not available from Docker Hub, build it locally with `./build.sh 0.0.11-gcp` and pass `--builder-image quex213/pack:0.0.11-gcp` (or keep the tag and the default applies).
- `docker` or `podman`, `sgdisk` (package `gdisk`), `mkfs.fat` (`dosfstools`), `mtools`.
- `gcloud` and `gsutil`, authenticated, with the Compute Engine API enabled and a GCS bucket in the project for staging.

## Build the image

```
scripts/gcp-build-image.sh \
  --image-name myvm-abc1234 \
  --bucket my-staging-bucket \
  docker-daemon:myimage:mytag
```

The script prints the UKI SHA-384, which is the expected RTMR[1] boot-application event. Record it with the container digest and the quex-pack commit: that triple is what verifiers rebuild.

Options worth knowing:

- `--vault-mrenclave HEX` if you run your own signed `quex-v1-vault` build. The default is the Quex vault identity baked into `quex-pack.sh`.
- `--ephemeral-key` disables vault delivery. `init` then generates a random key on every boot, so the TD address changes with every restart, anything registered on-chain for it becomes stale and data encrypted to the TD public key is lost. Use it only to smoke-test boot and networking.
- `--debug` switches to the debug kernel with the console on the serial port. It produces a different measurement and leaks the boot and workload logs. Never for production.

## Create the instance

```
scripts/gcp-create-instance.sh --name myvm-1 --image myvm-abc1234 --zone europe-west4-a
```

Firewall: open the workload ports as usual, and open TCP 24516 only from the host that runs `quex-v1-vault`:

```
gcloud compute firewall-rules create allow-td-key-delivery \
  --direction=INGRESS --action=ALLOW --rules=tcp:24516 \
  --source-ranges=<vault-host-ip>/32
```

## Deliver the key

From the `quex-v1-vault` folder on the SGX machine:

```
./setup_key.py <external-ip>:24516
```

The TD starts the workload once the key is in place. The key is derived from the vault seed and the TD measurement, so the same image gets the same key after a reboot or a re-create.

## Debugging

Build with `--debug`, then:

```
gcloud compute instances get-serial-port-output myvm-1 --zone europe-west4-a
```

## Verifying a running TD

1. Rebuild the UKI from the published container digest and quex-pack commit with the same options; `scripts/gcp-build-image.sh -o ukernel.efi` keeps the file. The build is reproducible, so the SHA-384 must match the published one.
2. Fetch the TD quote and CC event log from the workload.
3. Check the Intel DCAP signature on the quote, replay the event log into RTMR[1] and confirm the boot-application event equals the UKI SHA-384.
