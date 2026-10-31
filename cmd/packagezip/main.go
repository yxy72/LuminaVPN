// packagezip builds the portable distribution archive from an explicit file list.
package main

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"netlaunch/internal/runtimebundle"
	"os"
	"path/filepath"
	"strings"
)

var entries = []string{
	"netlaunch", "README.md", "THIRD_PARTY.md", "examples/policy.json", "examples/bootstrap.json",
	"licenses/golang-x-sys.txt",
	"runtime/manifest.json", "runtime/bin/mihomo", "runtime/bin/openconnect",
	"runtime/lib/libcrypto.3.dylib", "runtime/lib/libssl.3.dylib",
	"runtime/notices/Go-LICENSE", "runtime/notices/mihomo-LICENSE", "runtime/notices/yaml-LICENSE",
	"runtime/notices/openconnect/COPYING.LGPL", "runtime/notices/openssl@3/LICENSE.txt",
	"初始化.command", "检查环境.command", "启动.command", "状态.command", "停止与恢复.command", "公司认证.command",
	"同步订阅.command", "检查配置.command", "诊断导出.command", "版本信息.command",
}

var windowsEntries = []string{
	"初始化.cmd", "检查环境.cmd", "启动.cmd", "状态.cmd", "停止与恢复.cmd", "公司认证.cmd",
	"同步订阅.cmd", "检查配置.cmd", "诊断导出.cmd", "版本信息.cmd",
}

func packageZIP(source, destination string) (err error) {
	return archiveEntries(source, destination, entries)
}
func packageWindowsZIP(source, destination string) error {
	m, e := runtimebundle.VerifyFor(filepath.Join(source, "runtime"), "windows", "amd64")
	if e != nil {
		return e
	}
	names := []string{"netlaunch.exe", "README.md", "THIRD_PARTY.md", "licenses/golang-x-sys.txt", "examples/policy.json", "runtime/manifest.json", "runtime/notices/Go-LICENSE", "runtime/notices/mihomo-LICENSE", "runtime/notices/yaml-LICENSE", "runtime/notices/openconnect/COPYING.LGPL", "runtime/notices/windows-components.txt"}
	names = append(names, "examples/bootstrap.json")
	names = append(names, windowsEntries...)
	for _, f := range m.Files {
		// A runtime manifest cannot pull arbitrary configuration or logs into
		// a package. Only executable dependencies and the public CA are bundled.
		if f.Path != "certs/ca-bundle.crt" && !(strings.HasPrefix(f.Path, "bin/") && (strings.HasSuffix(f.Path, ".exe") || strings.HasSuffix(f.Path, ".dll")) && strings.Count(f.Path, "/") == 1) {
			return errors.New("unexpected Windows runtime package entry")
		}
		names = append(names, "runtime/"+f.Path)
	}
	return archiveEntries(source, destination, names)
}
func archiveEntries(source, destination string, names []string) (err error) {
	output, err := os.CreateTemp(filepath.Dir(destination), ".archive-")
	if err != nil {
		return err
	}
	defer func() { output.Close(); os.Remove(output.Name()) }()
	z := zip.NewWriter(output)
	for _, name := range names {
		path := filepath.Join(source, name)
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return errors.New("distribution input must be a regular file")
		}
		h, e := zip.FileInfoHeader(info)
		if e != nil {
			return e
		}
		h.Name = filepath.ToSlash(filepath.Join(filepath.Base(source), name))
		// Archive permissions describe the target distribution, not the host
		// filesystem (Windows does not retain Unix executable permission bits).
		mode := os.FileMode(0644)
		if name == "netlaunch" || name == "runtime/bin/mihomo" || name == "runtime/bin/openconnect" || strings.HasSuffix(name, ".command") {
			mode = 0755
		}
		h.SetMode(mode)
		h.Method = zip.Deflate
		writer, e := z.CreateHeader(h)
		if e != nil {
			return e
		}
		in, e := os.Open(path)
		if e != nil {
			return e
		}
		_, e = io.Copy(writer, in)
		in.Close()
		if e != nil {
			return e
		}
	}
	if err = z.Close(); err != nil {
		return err
	}
	if err = output.Sync(); err != nil {
		return err
	}
	if err = output.Close(); err != nil {
		return err
	}
	if err = os.Chmod(output.Name(), 0644); err != nil {
		return err
	}
	return os.Rename(output.Name(), destination)
}
func main() {
	if len(os.Args) != 3 && len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: packagezip SOURCE OUTPUT.zip [windows]")
		os.Exit(1)
	}
	pack := packageZIP
	if len(os.Args) == 4 {
		if os.Args[3] != "windows" {
			fmt.Fprintln(os.Stderr, "unsupported target")
			os.Exit(1)
		}
		pack = packageWindowsZIP
	}
	if e := pack(os.Args[1], os.Args[2]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
