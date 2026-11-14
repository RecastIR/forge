"""Provision the pinned fixture images or identify an already prepared local image."""
import argparse
import hashlib
from pathlib import Path
import subprocess

SUITE = Path(__file__).resolve().parent


def image_tag(suite, target):
    # A reference image contains host/guest protocol code as well as the pinned OS.
    # Include the Dockerfile's COPY inputs so stale images from another checkout
    # cannot silently run an earlier capture implementation.
    inputs = ["toolchain/Dockerfile"]
    if target == "reference":
        inputs.extend(("reference/capture.c", "build.py", "manifests.py",
                       "reference/guest.py", "reference/protocol.py"))
    digest = hashlib.sha256()
    for name in inputs:
        digest.update(name.encode() + b"\0" + (suite / name).read_bytes() + b"\0")
    return f"forge-windows-{target}:{digest.hexdigest()}"


def local_image(suite, target):
    tag = image_tag(suite, target)
    inspection = subprocess.run(["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}} {{.Id}}",
                                 tag], capture_output=True, text=True)
    if inspection.returncode:
        raise ValueError(f"Cannot use prepared {target} image. Run 'make provision-fixtures'. "
                         f"{inspection.stderr.strip()}")
    platform, image_id = inspection.stdout.split()
    if platform != "linux/amd64":
        raise ValueError(f"Unexpected {target} image platform {platform!r}. Run 'make provision-fixtures'.")
    return image_id


def reference_environment(suite):
    image = local_image(suite, "reference")
    host = subprocess.check_output(["docker", "info", "--format", "{{.Architecture}}"], text=True).strip()
    return dict(container_image_id=image, container_platform="linux/amd64", docker_host_arch=host)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--provision", action="store_true")
    action.add_argument("--id", choices=("toolchain", "reference"))
    args = parser.parse_args()
    try:
        if args.provision:
            for stage in ("toolchain", "reference"):
                subprocess.run(["docker", "build", "--platform", "linux/amd64", "--target", stage,
                                "-t", image_tag(SUITE, stage), "-f", SUITE / "toolchain/Dockerfile", SUITE], check=True)
        else:
            print(local_image(SUITE, args.id))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"{exc}\n")
