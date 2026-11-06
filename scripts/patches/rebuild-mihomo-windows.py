#!/usr/bin/env python3
"""Build the reviewed Windows-only Mihomo derivative into a NEW output directory.

Requires an existing checkout containing the pinned upstream Git commit and an
already populated Go module cache. Does not download dependencies, run Mihomo,
install a runtime, change a manifest, or modify the supplied checkout.
"""

import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile

COMMIT = "88dcbf7f1614a67c3b36b848ee3592dfa92ada36"
PATCH = "mihomo-v1.19.32-fakeip-pool-reuse.patch"
PATCH_SHA256 = "c24128f5c65899942a1065530ff7c3bc442f4dc8528e318b9e6d66a7c8e2e91e"
VERSION = "v1.19.32-lumina.1"
BUILD_TIME = "2026-09-30T22:35:49+08:00"
UPSTREAM_SHA256 = {
    "component/fakeip/pool.go": "19aabfc35a6d8f52d5be97db7e307e639b2413416eb91494554e28fa6cfda73e",
    "dns/enhancer.go": "6baa4319eb21de2dda1a65ac070dc327ebd00950957a3926f28ac5f395f15306",
    "LICENSE": "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
    "go.mod": "72b10f80ec33e2e06dee425a75e499d5818039c99d4e25f745d0bca349c90af5",
    "go.sum": "8fa2b10fe8589a4a1118fd6819f59231f74a27e71c8154de9c3903a69c3735aa",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def command(argv, *, cwd, env=None, timeout=60):
    result = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError("Command failed: " + repr(argv) + "\n"
                           + result.stderr.decode("utf-8", errors="replace")[-8000:])
    return result.stdout


def extract_fixed_archive(data, destination):
    total = 0
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if (not member.name or "\\" in member.name or path.is_absolute()
                    or any(part in ("", ".", "..") for part in path.parts)
                    or member.name in seen or not (member.isfile() or member.isdir())):
                raise ValueError("Unsupported source archive member")
            seen.add(member.name)
            total += member.size
            if member.size > 64 << 20 or total > 256 << 20 or len(seen) > 20000:
                raise ValueError("Source archive exceeds fixed bounds")
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("Missing source archive content")
                with stream, target.open("xb") as output:
                    shutil.copyfileobj(stream, output)


def main():
    if os.name != "nt":
        raise RuntimeError("This recipe runs its pure Windows tests on a Windows host")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", required=True, type=Path,
                        help="Existing upstream Git checkout; worktree contents are not used")
    parser.add_argument("--go", required=True, type=Path, help="Reviewed Go compiler executable")
    parser.add_argument("--module-cache", required=True, type=Path,
                        help="Prepopulated dependency cache matching fixed go.sum")
    parser.add_argument("--output-dir", required=True, type=Path,
                        help="New directory for source copy, logs, cache and Windows binary")
    args = parser.parse_args()
    source, compiler, modules, output = (value.resolve() for value in
                                        (args.source_dir, args.go, args.module_cache, args.output_dir))
    if not source.is_dir() or not compiler.is_file() or not modules.is_dir():
        raise ValueError("Missing source checkout, compiler or populated module cache")
    if output.exists() or output.is_symlink():
        raise ValueError("Output directory must not exist; no runtime replacement is performed")
    patch = Path(__file__).resolve().with_name(PATCH)
    patch_bytes = patch.read_bytes()
    if sha(patch_bytes) != PATCH_SHA256:
        raise ValueError("Reviewed patch SHA256 differs")
    git = shutil.which("git")
    if not git:
        raise ValueError("Git is required to export the fixed commit")
    git_argv = [git, "--no-replace-objects", "-c", "core.autocrlf=false", "-c", "core.eol=lf"]
    observed = command(git_argv + ["rev-parse", COMMIT + "^{commit}"], cwd=source).decode("ascii").strip()
    if observed != COMMIT:
        raise ValueError("Pinned upstream commit unavailable")
    timestamp = int(command(git_argv + ["show", "-s", "--format=%ct", COMMIT], cwd=source).decode("ascii").strip())
    if timestamp != int(datetime.datetime.fromisoformat(BUILD_TIME).timestamp()):
        raise ValueError("Pinned source timestamp differs")
    build_time = BUILD_TIME
    source_archive = command(git_argv + ["archive", "--format=tar", COMMIT], cwd=source)
    output.mkdir(parents=True)
    work = output / "source"
    work.mkdir()
    extract_fixed_archive(source_archive, work)
    for name, expected in UPSTREAM_SHA256.items():
        if sha((work / name).read_bytes()) != expected:
            raise ValueError("Fixed upstream file differs: " + name)
    frozen_patch = output / PATCH
    frozen_patch.write_bytes(patch_bytes)
    command(git_argv + ["apply", "--check", str(frozen_patch)], cwd=work)
    command(git_argv + ["apply", str(frozen_patch)], cwd=work)
    env = dict(os.environ)
    env.update({"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local",
                "GOPROXY": "off", "GOSUMDB": "sum.golang.org", "GOMODCACHE": str(modules),
                "GOCACHE": str(output / "go-cache"), "GOOS": "windows", "GOARCH": "amd64",
                "GOAMD64": "v1", "CGO_ENABLED": "0", "GOFLAGS": "-mod=readonly"})
    compiler_version = command([str(compiler), "version"], cwd=work, env=env).decode("utf-8", errors="replace").strip()
    if "go1.27.3 " not in compiler_version:
        raise ValueError("This reviewed build recipe requires Go 1.27.3")
    verification = command([str(compiler), "mod", "verify"], cwd=work, env=env, timeout=300)
    (output / "modules-verify.stdout.txt").write_bytes(verification)
    test_args = [str(compiler), "test", "-count=1", "-tags", "with_gvisor",
                 "./component/fakeip", "./dns", "-run", "^TestLumina"]
    test_output = command(test_args, cwd=work, env=env, timeout=900)
    (output / "pure-tests.stdout.txt").write_bytes(test_output)
    image = output / "mihomo.exe"
    ldflags = ("-w -s -buildid= -X github.com/metacubex/mihomo/constant.Version=" + VERSION
               + " -X github.com/metacubex/mihomo/constant.BuildTime=" + build_time)
    build_args = [str(compiler), "build", "-tags", "with_gvisor", "-trimpath", "-buildvcs=false",
                  "-ldflags", ldflags, "-o", str(image), "."]
    build_output = command(build_args, cwd=work, env=env, timeout=900)
    (output / "build.stdout.txt").write_bytes(build_output)
    metadata = command([str(compiler), "version", "-m", str(image)], cwd=work, env=env)
    (output / "binary-buildinfo.txt").write_bytes(metadata)
    report = {"version": 1, "upstream_commit": COMMIT, "patch_sha256": PATCH_SHA256,
              "source_archive_sha256": sha(source_archive), "upstream_files": UPSTREAM_SHA256,
              "go_version": compiler_version, "go_sha256": sha(compiler.read_bytes()),
              "target": "windows/amd64/v1", "cgo_enabled": False, "tags": ["with_gvisor"],
              "binary_version": VERSION, "build_time_from_source_commit": build_time,
              "test_argv": test_args, "build_argv": build_args,
              "modules_verify_stdout_sha256": sha(verification),
              "tests_stdout_sha256": sha(test_output), "buildinfo_sha256": sha(metadata),
              "binary_sha256": sha(image.read_bytes()), "binary_bytes": image.stat().st_size,
              "core_executed": False, "runtime_installed": False, "manifest_modified": False}
    (output / "build-provenance.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
