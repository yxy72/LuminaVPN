#!/usr/bin/env python3
"""Build the reviewed fake-IP patch for macOS arm64 into a new directory."""

import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import runpy
import shutil


def main():
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        raise RuntimeError("The recipe runs its source tests on an Apple Silicon Mac")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", required=True, type=Path, help="Existing pinned upstream Git checkout")
    parser.add_argument("--go", required=True, type=Path, help="Go 1.27.3 executable")
    parser.add_argument("--module-cache", required=True, type=Path, help="Prepopulated module cache matching go.sum")
    parser.add_argument("--output-dir", required=True, type=Path, help="New local directory for source and outputs")
    args = parser.parse_args()
    if args.output_dir.is_symlink():
        raise ValueError("Output may not be a symbolic link")
    source, compiler, modules, output = (value.resolve() for value in
                                        (args.source_dir, args.go, args.module_cache, args.output_dir))
    if not source.is_dir() or not compiler.is_file() or not modules.is_dir():
        raise ValueError("Source, compiler and module cache must already exist")
    if output.exists() or output.is_relative_to(source) or output.is_relative_to(modules):
        raise ValueError("Output must be a new directory outside the checkout and module cache")

    # Reuse the reviewed source/export validation without changing the hashed
    # Windows build recipe or its provenance.
    scripts = Path(__file__).resolve().parent
    reviewed = runpy.run_path(str(scripts / "rebuild-mihomo-windows.py"))
    command, sha = reviewed["command"], reviewed["sha"]
    commit, build_time = reviewed["COMMIT"], reviewed["BUILD_TIME"]
    patch = scripts / reviewed["PATCH"]
    patch_bytes = patch.read_bytes()
    if sha(patch_bytes) != reviewed["PATCH_SHA256"]:
        raise ValueError("Reviewed patch SHA256 differs")
    git = shutil.which("git")
    if not git:
        raise ValueError("Git is required to export the fixed commit")
    git_argv = [git, "--no-replace-objects", "-c", "core.autocrlf=false", "-c", "core.eol=lf"]
    observed = command(git_argv + ["rev-parse", commit + "^{commit}"], cwd=source).decode("ascii").strip()
    if observed != commit:
        raise ValueError("Pinned upstream commit unavailable")
    timestamp = int(command(git_argv + ["show", "-s", "--format=%ct", commit], cwd=source))
    if timestamp != int(datetime.datetime.fromisoformat(build_time).timestamp()):
        raise ValueError("Pinned source timestamp differs")
    source_archive = command(git_argv + ["archive", "--format=tar", commit], cwd=source)
    os.umask(0o077)
    output.mkdir(parents=True)
    work = output / "source"
    work.mkdir()
    reviewed["extract_fixed_archive"](source_archive, work)
    for name, expected in reviewed["UPSTREAM_SHA256"].items():
        if sha((work / name).read_bytes()) != expected:
            raise ValueError("Fixed upstream file differs: " + name)
    frozen_patch = output / patch.name
    frozen_patch.write_bytes(patch_bytes)
    command(git_argv + ["apply", "--check", str(frozen_patch)], cwd=work)
    command(git_argv + ["apply", str(frozen_patch)], cwd=work)

    env = dict(os.environ)
    env.update({"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local",
                "GOPROXY": "off", "GOSUMDB": "sum.golang.org", "GOMODCACHE": str(modules),
                "GOCACHE": str(output / "go-cache"), "GOOS": "darwin", "GOARCH": "arm64",
                "GOARM64": "v8.0", "CGO_ENABLED": "0", "GOFLAGS": "-mod=readonly"})
    version = command([str(compiler), "version"], cwd=work, env=env).decode("ascii").strip()
    if version != "go version go1.27.3 darwin/arm64":
        raise ValueError("This recipe requires native Apple Silicon Go 1.27.3")
    reviewed_go = version.split()[2]
    verification = command([str(compiler), "mod", "verify"], cwd=work, env=env, timeout=300)
    tests = command([str(compiler), "test", "-count=1", "-tags", "with_gvisor",
                     "./component/fakeip", "./dns", "-run", "^TestLumina"], cwd=work, env=env, timeout=900)
    binary = output / "mihomo"
    ldflags = ("-w -s -buildid= -X github.com/metacubex/mihomo/constant.Version=" + reviewed["VERSION"]
               + " -X github.com/metacubex/mihomo/constant.BuildTime=" + build_time)
    command([str(compiler), "build", "-tags", "with_gvisor", "-trimpath", "-buildvcs=false",
             "-ldflags", ldflags, "-o", str(binary), "."], cwd=work, env=env, timeout=900)
    metadata = command([str(compiler), "version", "-m", str(binary)], cwd=work, env=env)
    (output / "modules-verify.stdout.txt").write_bytes(verification)
    (output / "pure-tests.stdout.txt").write_bytes(tests)
    (output / "binary-buildinfo.txt").write_bytes(metadata)
    report = {"version": 1, "upstream_commit": commit, "patch_sha256": sha(patch_bytes),
              "source_archive_sha256": sha(source_archive), "go_version": reviewed_go,
              "go_sha256": sha(compiler.read_bytes()), "target": "darwin/arm64/v8.0",
              "cgo_enabled": False, "tags": ["with_gvisor"], "binary_version": reviewed["VERSION"],
              "build_time_from_source_commit": build_time, "binary_sha256": sha(binary.read_bytes()),
              "binary_bytes": binary.stat().st_size}
    (output / "build-provenance.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(binary)


if __name__ == "__main__":
    main()
