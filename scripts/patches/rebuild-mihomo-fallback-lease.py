#!/usr/bin/env python3
"""Rebuild v1.19.32-lumina.2 using the pinned Git source and offline Go cache."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil


SCRIPT_DIR = Path(__file__).resolve().parent
PROVENANCE = SCRIPT_DIR / "mihomo-v1.19.32-personal-fallback-lease.provenance.json"
TESTS = (
    ("fakeip", "./component/fakeip", "^TestLumina"),
    ("dns", "./dns", "^TestLumina"),
    ("outboundgroup", "./adapter/outboundgroup", "^TestLuminaFallback"),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=("darwin/arm64", "windows/amd64"))
    parser.add_argument("--source-dir", required=True, type=Path, help="Upstream Git checkout with the fixed commit")
    parser.add_argument("--go", required=True, type=Path, help="Pinned Go 1.27.3 executable for the build host")
    parser.add_argument("--module-cache", required=True, type=Path, help="Prepopulated module cache matching go.sum")
    parser.add_argument("--output-dir", required=True, type=Path, help="New directory for source, binary and local verification files")
    args = parser.parse_args()
    if args.output_dir.is_symlink():
        raise ValueError("Output may not be a symbolic link")
    source, compiler, modules, output = (value.resolve() for value in (
        args.source_dir, args.go, args.module_cache, args.output_dir,
    ))
    if not source.is_dir() or not compiler.is_file() or not modules.is_dir():
        raise ValueError("Source checkout, Go compiler and module cache must already exist")
    if output.exists() or output.is_relative_to(source) or output.is_relative_to(modules):
        raise ValueError("Output must be a new directory outside the source checkout and module cache")

    provenance_bytes = PROVENANCE.read_bytes()
    provenance = json.loads(provenance_bytes)
    base_script = SCRIPT_DIR / "rebuild-mihomo-windows.py"
    if hashlib.sha256(base_script.read_bytes()).hexdigest() != provenance["base_recipe_sha256"]:
        raise ValueError("Reviewed fake-IP build recipe differs")
    reviewed = runpy.run_path(str(base_script))
    command, sha = reviewed["command"], reviewed["sha"]
    commit, build_time = reviewed["COMMIT"], reviewed["BUILD_TIME"]
    if commit != provenance["upstream_commit"] or build_time != provenance["upstream_commit_build_time"]:
        raise ValueError("Build provenance differs from the reviewed upstream identity")
    patches = []
    for name, digest in (
        (reviewed["PATCH"], reviewed["PATCH_SHA256"]),
        ("mihomo-v1.19.32-personal-fallback-lease.patch", provenance["lease_patch_sha256"]),
    ):
        data = (SCRIPT_DIR / name).read_bytes()
        if sha(data) != digest:
            raise ValueError("Reviewed patch SHA256 differs: " + name)
        patches.append((name, data))

    git = shutil.which("git")
    if not git:
        raise ValueError("Git is required to export the fixed commit")
    git_cmd = [git, "--no-replace-objects", "-c", "core.autocrlf=false", "-c", "core.eol=lf"]
    git_env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    git_env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
    observed = command(git_cmd + ["rev-parse", commit + "^{commit}"], cwd=source, env=git_env).decode("ascii").strip()
    timestamp = int(command(git_cmd + ["show", "-s", "--format=%ct", commit], cwd=source, env=git_env))
    if observed != commit or timestamp != int(datetime.datetime.fromisoformat(build_time).timestamp()):
        raise ValueError("Pinned upstream commit or timestamp differs")
    archive = command(git_cmd + ["archive", "--format=tar", commit], cwd=source, env=git_env)
    if sha(archive) != provenance["source_archive_sha256"]:
        raise ValueError("Pinned source archive differs")

    compiler_sha = sha(compiler.read_bytes())
    host = next((host for host, digest in provenance["compiler_sha256"].items() if digest == compiler_sha), None)
    if host is None:
        raise ValueError("Unreviewed Go compiler for the build host")
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(("GO", "CGO_"))}
    target_os, target_arch = args.target.split("/")
    env.update({"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local",
                "GOPROXY": "off", "GOSUMDB": "sum.golang.org", "GOMODCACHE": str(modules),
                "GOCACHE": str(output / "go-cache"), "GOOS": target_os, "GOARCH": target_arch,
                "GOARM64": "v8.0", "GOAMD64": "v1", "CGO_ENABLED": "0", "GOFLAGS": "-mod=readonly"})
    go = [str(compiler)]
    version = command(go + ["version"], cwd=source, env=env).decode("ascii").strip()
    if version != "go version " + provenance["go_version"] + " " + host:
        raise ValueError("Pinned Go compiler version or host differs")

    os.umask(0o077)
    output.mkdir(parents=True)
    work = output / "source"
    work.mkdir()
    reviewed["extract_fixed_archive"](archive, work)
    git_env["GIT_CEILING_DIRECTORIES"] = str(output)
    for name, data in patches:
        frozen_patch = output / name
        frozen_patch.write_bytes(data)
        command(git_cmd + ["apply", "--check", str(frozen_patch)], cwd=work, env=git_env)
        command(git_cmd + ["apply", str(frozen_patch)], cwd=work, env=git_env)

    verified = command(go + ["mod", "verify"], cwd=work, env=env, timeout=300)
    (output / "modules-verify.stdout.txt").write_bytes(verified)
    native = host == args.target
    extension = ".exe" if target_os == "windows" else ""
    for name, package, pattern in TESTS:
        test = go + ["test", "-tags", "with_gvisor"]
        if native:
            listed = command(test + ["-list", pattern, package], cwd=work, env=env, timeout=900)
            if not any(line.startswith(b"TestLumina") for line in listed.splitlines()):
                raise ValueError("Pinned regression tests missing from " + package)
            ran = command(test + ["-count=1", "-run", pattern, package], cwd=work, env=env, timeout=900)
            (output / (name + "-tests.stdout.txt")).write_bytes(ran)
        else:
            test_image = output / (name + ".test" + extension)
            command(test + ["-c", "-o", str(test_image), package], cwd=work, env=env, timeout=900)
            if not test_image.is_file():
                raise ValueError("Cross-compiled regression tests missing from " + package)

    binary = output / ("mihomo" + extension)
    binary_version = provenance["binary_version"]
    ldflags = ("-w -s -buildid= -X github.com/metacubex/mihomo/constant.Version=" + binary_version
               + " -X github.com/metacubex/mihomo/constant.BuildTime=" + build_time)
    command(go + ["build", "-tags", "with_gvisor", "-trimpath", "-buildvcs=false", "-ldflags", ldflags,
                  "-o", str(binary), "."], cwd=work, env=env, timeout=900)
    binary_sha = sha(binary.read_bytes())
    if binary_sha != provenance["binary_sha256"][args.target]:
        raise ValueError("Rebuilt target SHA256 differs: " + binary_sha)
    metadata = command(go + ["version", "-m", str(binary)], cwd=work, env=env)
    (output / "binary-buildinfo.txt").write_bytes(metadata)
    report = {
        "version": 1,
        "recipe_sha256": sha(Path(__file__).read_bytes()),
        "source_provenance_sha256": sha(provenance_bytes),
        "source_archive_sha256": sha(archive),
        "upstream_commit": commit,
        "patch_sha256": {name: sha(data) for name, data in patches},
        "go_version": version,
        "go_sha256": compiler_sha,
        "target": args.target,
        "target_level": "v8.0" if target_os == "darwin" else "v1",
        "tags": ["with_gvisor"],
        "cgo_enabled": False,
        "tests": "native" if native else "cross-compiled",
        "binary_version": binary_version,
        "build_time_from_source_commit": build_time,
        "binary_sha256": binary_sha,
        "binary_bytes": binary.stat().st_size,
    }
    (output / "build-provenance.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(binary)


if __name__ == "__main__":
    main()
