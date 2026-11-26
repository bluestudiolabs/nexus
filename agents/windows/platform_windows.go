package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var k32 = syscall.NewLazyDLL("kernel32.dll")
var adv = syscall.NewLazyDLL("advapi32.dll")
var crypt = syscall.NewLazyDLL("crypt32.dll")
var psapi = syscall.NewLazyDLL("psapi.dll")
var iphlp = syscall.NewLazyDLL("iphlpapi.dll")

func ptr(p any) uintptr {
	switch x := p.(type) {
	case *uint16:
		return uintptr(unsafe.Pointer(x))
	case *uint32:
		return uintptr(unsafe.Pointer(x))
	case *syscall.Handle:
		return uintptr(unsafe.Pointer(x))
	case *byte:
		return uintptr(unsafe.Pointer(x))
	}
	panic("ptr")
}
func w(s string) *uint16   { p, _ := syscall.UTF16PtrFromString(s); return p }
func dir() string          { return filepath.Join(os.Getenv("LOCALAPPDATA"), "NexusNativeAgent") }
func installed() string    { return filepath.Join(dir(), "NexusAgent.exe") }
func configPath() string   { return filepath.Join(dir(), "config.json") }
func exists(p string) bool { _, e := os.Stat(p); return e == nil }
func atomic(p string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(p), ".nexus-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), p)
}
func load() (Config, error) {
	var c Config
	b, e := os.ReadFile(configPath())
	if e == nil {
		e = json.Unmarshal(b, &c)
	}
	if e == nil {
		c.Server, e = origin(c.Server)
	}
	return c, e
}
func save(c Config) error {
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	return atomic(configPath(), b)
}

type blob struct {
	Size uint32
	Data *byte
}

func dpapi(b []byte, unprotect bool) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("Empty credential")
	}
	in := blob{uint32(len(b)), &b[0]}
	var out blob
	name := "CryptProtectData"
	if unprotect {
		name = "CryptUnprotectData"
	}
	r, _, e := crypt.NewProc(name).Call(uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&out)))
	runtime.KeepAlive(b)
	if r == 0 {
		return nil, e
	}
	defer k32.NewProc("LocalFree").Call(uintptr(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}

const hkcu = syscall.Handle(0x80000001)
const hklm = syscall.Handle(0x80000002)

func readReg(root syscall.Handle, path, name string) string {
	var h syscall.Handle
	if syscall.RegOpenKeyEx(root, w(path), 0, 0x20019, &h) != nil {
		return ""
	}
	defer syscall.RegCloseKey(h)
	var n, t uint32
	if syscall.RegQueryValueEx(h, w(name), nil, &t, nil, &n) != nil || n < 2 || n > 8192 || t != 1 {
		return ""
	}
	b := make([]uint16, (n+1)/2)
	if syscall.RegQueryValueEx(h, w(name), nil, &t, (*byte)(unsafe.Pointer(&b[0])), &n) != nil {
		return ""
	}
	return syscall.UTF16ToString(b)
}
func writeReg(path, name, value string) error {
	var h syscall.Handle
	var disp uint32
	r, _, _ := adv.NewProc("RegCreateKeyExW").Call(uintptr(hkcu), ptr(w(path)), 0, 0, 0, 0x20006, 0, ptr(&h), ptr(&disp))
	if r != 0 {
		return syscall.Errno(r)
	}
	defer syscall.RegCloseKey(h)
	b, _ := syscall.UTF16FromString(value)
	r, _, _ = adv.NewProc("RegSetValueExW").Call(uintptr(h), ptr(w(name)), 0, 1, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)*2))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const uninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall\NexusNativeAgent`

func delRegValue(path, name string) error {
	var h syscall.Handle
	e := syscall.RegOpenKeyEx(hkcu, w(path), 0, 0x20006, &h)
	if e == syscall.ERROR_FILE_NOT_FOUND {
		return nil
	}
	if e != nil {
		return e
	}
	defer syscall.RegCloseKey(h)
	r, _, _ := adv.NewProc("RegDeleteValueW").Call(uintptr(h), ptr(w(name)))
	if r != 0 && r != 2 {
		return syscall.Errno(r)
	}
	return nil
}
func register() error {
	for _, x := range [][3]string{{uninstallKey, "DisplayName", "NEXUS Native Agent"}, {uninstallKey, "DisplayVersion", "3.0.1"}, {uninstallKey, "Publisher", "NEXUS (local build)"}, {uninstallKey, "UninstallString", `"` + installed() + `" --uninstall`}, {uninstallKey, "InstallLocation", dir()}, {runKey, "NexusNativeAgent", `"` + installed() + `" --monitor`}} {
		if e := writeReg(x[0], x[1], x[2]); e != nil {
			return e
		}
	}
	return nil
}
func unregister() error {
	if e := delRegValue(runKey, "NexusNativeAgent"); e != nil {
		return e
	}
	r, _, _ := adv.NewProc("RegDeleteKeyW").Call(uintptr(hkcu), ptr(w(uninstallKey)))
	if r != 0 && r != 2 {
		return syscall.Errno(r)
	}
	return nil
}
func start(path string, args ...string) error {
	c := exec.Command(path, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if e := c.Start(); e != nil {
		return e
	}
	return c.Process.Release()
}
func copySelf(dst string) error {
	src, e := os.Executable()
	if e != nil {
		return e
	}
	if strings.EqualFold(src, dst) {
		return nil
	}
	b, e := os.ReadFile(src)
	if e != nil {
		return e
	}
	if old, e := os.ReadFile(dst); e == nil {
		if bytes.Equal(old, b) {
			return nil
		}
		return errors.New("A different native agent is installed. Uninstall it before replacing its executable.")
	}
	return atomic(dst, b)
}
func status(s string) {
	_ = atomic(filepath.Join(dir(), "status.txt"), []byte(time.Now().Format("2006-01-02 15:04:05")+"  "+s))
}
func filetime(f syscall.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }

type memstat struct {
	Length, Load                                                                 uint32
	Total, Available, PageTotal, PageAvail, VirtualTotal, VirtualAvail, Extended uint64
}
type pmc struct {
	CB, Faults                                                                                       uint32
	PeakWS, WS, QuotaPeakPaged, QuotaPaged, QuotaPeakNonPaged, QuotaNonPaged, Pagefile, PeakPagefile uintptr
}
type counter struct {
	Idle, Kernel, User, Self uint64
	At                       time.Time
	Net                      map[uint32][2]uint32
}

func netCounters() map[uint32][2]uint32 {
	var n uint32
	iphlp.NewProc("GetIfTable").Call(0, ptr(&n), 0)
	if n < 4 || n > 16<<20 {
		return nil
	}
	b := make([]byte, n)
	r, _, _ := iphlp.NewProc("GetIfTable").Call(uintptr(unsafe.Pointer(&b[0])), ptr(&n), 0)
	if r != 0 {
		return nil
	}
	u := func(off int) uint32 { return *(*uint32)(unsafe.Pointer(&b[off])) }
	m := map[uint32][2]uint32{}
	for i := 0; i < int(u(0)) && 4+(i+1)*860 <= int(n); i++ {
		p := 4 + i*860
		typ, op := u(p+516), u(p+544)
		if (typ == 6 || typ == 71) && op == 5 {
			m[u(p+512)] = [2]uint32{u(p + 552), u(p + 576)}
		}
	}
	return m
}
func sample(prev *counter, gpu bool) map[string]any {
	d := map[string]any{"cpuCores": runtime.NumCPU()}
	var idle, k, u syscall.Filetime
	r, _, _ := k32.NewProc("GetSystemTimes").Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u)))
	now := time.Now()
	next := counter{Idle: filetime(idle), Kernel: filetime(k), User: filetime(u), At: now}
	if r != 0 && prev.Kernel > 0 && next.Kernel >= prev.Kernel && next.User >= prev.User && next.Idle >= prev.Idle {
		total := next.Kernel - prev.Kernel + next.User - prev.User
		id := next.Idle - prev.Idle
		if total > 0 && id <= total {
			d["cpu"] = 100 * float64(total-id) / float64(total)
		}
	}
	m := memstat{Length: uint32(unsafe.Sizeof(memstat{}))}
	if r, _, _ := k32.NewProc("GlobalMemoryStatusEx").Call(uintptr(unsafe.Pointer(&m))); r != 0 && m.Total > 0 {
		d["ram"] = 100 * float64(m.Total-m.Available) / float64(m.Total)
		d["ramTotal"] = m.Total
	}
	var a, b, c uint64
	root := os.Getenv("SystemDrive") + `\`
	if r, _, _ := k32.NewProc("GetDiskFreeSpaceExW").Call(ptr(w(root)), uintptr(unsafe.Pointer(&a)), uintptr(unsafe.Pointer(&b)), uintptr(unsafe.Pointer(&c))); r != 0 {
		d["diskFree"] = a
		d["diskTotal"] = b
	}
	up, _, _ := k32.NewProc("GetTickCount64").Call()
	d["uptime"] = float64(up) / 1000
	h, _ := syscall.GetCurrentProcess()
	var ct, et, kt, ut syscall.Filetime
	if syscall.GetProcessTimes(h, &ct, &et, &kt, &ut) == nil {
		next.Self = filetime(kt) + filetime(ut)
		if prev.Self > 0 && next.Self >= prev.Self && !prev.At.IsZero() {
			v := 100 * float64(next.Self-prev.Self) / 1e7 / now.Sub(prev.At).Seconds() / float64(runtime.NumCPU())
			if v >= 0 && v <= 100 {
				d["agentCpu"] = v
			}
		}
	}
	p := pmc{CB: uint32(unsafe.Sizeof(pmc{}))}
	if r, _, _ := psapi.NewProc("GetProcessMemoryInfo").Call(uintptr(h), uintptr(unsafe.Pointer(&p)), uintptr(p.CB)); r != 0 {
		d["agentRam"] = p.WS
	}
	next.Net = netCounters()
	if !prev.At.IsZero() && len(next.Net) > 0 {
		var rx, tx uint64
		for id, v := range next.Net {
			if o, ok := prev.Net[id]; ok {
				rx += uint64(v[0] - o[0])
				tx += uint64(v[1] - o[1])
			}
		}
		dt := now.Sub(prev.At).Seconds()
		if dt > 0 && dt < 20 {
			d["rx"] = float64(rx) / dt
			d["tx"] = float64(tx) / dt
		}
	}
	*prev = next
	d["cpuName"] = readReg(hklm, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString")
	d["model"] = readReg(hklm, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemProductName")
	d["osName"] = "Windows build " + readReg(hklm, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "CurrentBuildNumber")
	if gpu {
		gpuSample(d)
	}
	return d
}
func gpuSample(d map[string]any) {
	for _, p := range []string{filepath.Join(os.Getenv("SystemRoot"), "System32", "nvidia-smi.exe"), filepath.Join(os.Getenv("ProgramFiles"), "NVIDIA Corporation", "NVSMI", "nvidia-smi.exe")} {
		if !exists(p) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cmd := exec.CommandContext(ctx, p, "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw", "--format=csv,noheader,nounits")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		b, e := cmd.Output()
		cancel()
		if e != nil {
			return
		}
		rd := csv.NewReader(strings.NewReader(string(b)))
		rd.TrimLeadingSpace = true
		row, e := rd.Read()
		if e != nil || len(row) != 6 {
			return
		}
		d["gpuName"] = row[0]
		for i, k := range map[int]string{1: "gpu", 4: "gpuTemp", 5: "gpuPower"} {
			if x, e := strconv.ParseFloat(strings.TrimSpace(row[i]), 64); e == nil {
				d[k] = x
			}
		}
		a, e := strconv.ParseFloat(strings.TrimSpace(row[2]), 64)
		b2, e2 := strconv.ParseFloat(strings.TrimSpace(row[3]), 64)
		if e == nil && e2 == nil && b2 > 0 {
			d["vram"] = 100 * a / b2
		}
		return
	}
}
func monitor() {
	for exists(configPath()) {
		raw, e := os.ReadFile(configPath())
		if e != nil {
			time.Sleep(time.Second)
			continue
		}
		c, e := load()
		if e != nil {
			status("Configuration error")
			time.Sleep(5 * time.Second)
			continue
		}
		token, e := dpapi(c.Token, true)
		if e != nil {
			status("Credential unavailable; pair again")
			waitConfig(raw)
			continue
		}
		h, e := client(c)
		if e != nil {
			status("TLS configuration error")
			waitConfig(raw)
			continue
		}
		prev := counter{}
		delay := 10 * time.Second
		for sameConfig(raw) {
			if exists(filepath.Join(dir(), "paused")) {
				status("Paused")
				prev = counter{}
				time.Sleep(3 * time.Second)
				continue
			}
			d := sample(&prev, c.GPU)
			if _, ok := d["cpu"]; !ok {
				time.Sleep(time.Second)
				continue
			}
			if !sameConfig(raw) || exists(filepath.Join(dir(), "paused")) {
				continue
			}
			e = ingest(h, c.Server, string(token), d)
			if e == nil {
				status("Connected - telemetry accepted")
				delay = 10 * time.Second
			} else if e == HTTPError(401) {
				status("Credential revoked - pair again")
				waitConfig(raw)
				break
			} else {
				status(fmt.Sprintf("Connection failed: %v", e))
				if delay < 60*time.Second {
					delay *= 2
					if delay > 60*time.Second {
						delay = 60 * time.Second
					}
				}
			}
			for i := time.Duration(0); i < delay && sameConfig(raw) && !exists(filepath.Join(dir(), "paused")); i += time.Second {
				time.Sleep(time.Second)
			}
		}
		h.CloseIdleConnections()
	}
}
func sameConfig(raw []byte) bool {
	b, e := os.ReadFile(configPath())
	return e == nil && bytes.Equal(raw, b)
}
func waitConfig(raw []byte) {
	for sameConfig(raw) {
		time.Sleep(2 * time.Second)
	}
}
