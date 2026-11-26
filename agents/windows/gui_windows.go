package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var user = syscall.NewLazyDLL("user32.dll")
var shell = syscall.NewLazyDLL("shell32.dll")
var comdlg = syscall.NewLazyDLL("comdlg32.dll")

func call(d *syscall.LazyDLL, n string, a ...uintptr) uintptr {
	r, _, _ := d.NewProc(n).Call(a...)
	return r
}
func uc(n string, a ...uintptr) uintptr { return call(user, n, a...) }
func msg(h uintptr, s string, flags uintptr) uintptr {
	return uc("MessageBoxW", h, ptr(w(s)), ptr(w("NEXUS Agent")), flags)
}
func text(h uintptr, s string) { uc("SetWindowTextW", h, ptr(w(s))) }
func get(h uintptr) string {
	b := make([]uint16, 8192)
	uc("GetWindowTextW", h, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	return syscall.UTF16ToString(b)
}

var hwnd, serverBox, codeBox, caBox, fpBox, gpuBox, statusBox, installBtn uintptr
var instance uintptr
var monitoring bool
var finishing bool

const wmCommand = 0x111
const wmTimer = 0x113
const wmClose = 0x10
const wmDestroy = 2
const wmTray = 0x8001
const wmResult = 0x8002

type outcome struct {
	message string
	ok      bool
}

var results = make(chan outcome, 1)
var wndproc = syscall.NewCallback(wnd)

type wndclass struct {
	Size, Style                        uint32
	Proc                               uintptr
	ClsExtra, WndExtra                 int32
	Instance, Icon, Cursor, Background uintptr
	Menu, Class                        *uint16
	SmallIcon                          uintptr
}
type point struct{ X, Y int32 }
type message struct {
	Hwnd           uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Pt             point
	Private        uint32
}
type notify struct {
	Size                uint32
	Hwnd                uintptr
	ID, Flags, Callback uint32
	Icon                uintptr
	Tip                 [128]uint16
	State, StateMask    uint32
	Info                [256]uint16
	Version             uint32
	Title               [64]uint16
	InfoFlags           uint32
	GUID                [16]byte
	BalloonIcon         uintptr
}

var tray notify

func initTray(h uintptr) {
	tray = notify{Size: uint32(unsafe.Sizeof(notify{})), Hwnd: h, ID: 1, Flags: 1 | 2 | 4, Callback: wmTray, Icon: uc("LoadIconW", 0, 32512)}
	copy(tray.Tip[:], syscall.StringToUTF16("NEXUS Agent - double-click to open"))
	call(shell, "Shell_NotifyIconW", 0, uintptr(unsafe.Pointer(&tray)))
}
func child(cls, s string, style uintptr, x, y, width, height, id int) uintptr {
	h := uc("CreateWindowExW", 0, ptr(w(cls)), ptr(w(s)), style|0x50000000, uintptr(x), uintptr(y), uintptr(width), uintptr(height), hwnd, uintptr(id), instance, 0)
	font := call(syscall.NewLazyDLL("gdi32.dll"), "GetStockObject", 17)
	uc("SendMessageW", h, 0x30, font, 1)
	return h
}
func label(s string, x, y, width int) { child("STATIC", s, 0, x, y, width, 22, 0) }
func edit(s string, x, y, width, id int, password bool) uintptr {
	style := uintptr(0x00800000 | 0x80 | 0x10000)
	if password {
		style |= 0x20
	}
	return child("EDIT", s, style, x, y, width, 28, id)
}
func btn(s string, x, y, width, id int) uintptr {
	return child("BUTTON", s, 0x10000, x, y, width, 32, id)
}

type openfile struct {
	Size                      uint32
	Owner, Instance           uintptr
	Filter, Custom            *uint16
	MaxCustom, FilterIndex    uint32
	File                      *uint16
	MaxFile                   uint32
	FileTitle                 *uint16
	MaxFileTitle              uint32
	InitialDir, Title         *uint16
	Flags                     uint32
	FileOffset, FileExtension uint16
	DefExt                    *uint16
	CustData, Hook            uintptr
	Template                  *uint16
	Reserved                  uintptr
	ReservedN, FlagsEx        uint32
}

func browse() {
	buf := make([]uint16, 4096)
	f := openfile{Size: uint32(unsafe.Sizeof(openfile{})), Owner: hwnd, File: &buf[0], MaxFile: uint32(len(buf)), Title: w("Select NEXUS CA certificate"), Flags: 0x1000 | 0x800 | 0x80000 | 0x8}
	if call(comdlg, "GetOpenFileNameW", uintptr(unsafe.Pointer(&f))) != 0 {
		text(caBox, syscall.UTF16ToString(buf))
	}
}
func showStatus() {
	if b, e := os.ReadFile(filepath.Join(dir(), "status.txt")); e == nil {
		text(statusBox, string(b))
	} else if exists(configPath()) {
		text(statusBox, "Installed - waiting for first sample")
	} else {
		text(statusBox, "Not installed")
	}
}
func install() {
	if finishing {
		return
	}
	base, e := origin(get(serverBox))
	if e != nil {
		msg(hwnd, e.Error(), 0x10)
		return
	}
	code := strings.TrimSpace(get(codeBox))
	gpu := uc("SendMessageW", gpuBox, 0xF0, 0, 0) == 1
	caPath := strings.TrimSpace(get(caBox))
	finger := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(get(fpBox)), ":", ""), " ", ""))
	c := Config{Server: base, GPU: gpu}
	if caPath != "" {
		b, e := os.ReadFile(caPath)
		if e != nil || len(b) > 65536 {
			msg(hwnd, "Cannot read CA file", 0x10)
			return
		}
		actual, e := caFingerprint(b)
		if e != nil || actual != finger {
			msg(hwnd, "CA fingerprint does not match. Use the SHA-256 fingerprint from your trusted Ubuntu terminal.", 0x10)
			return
		}
		c.CA = string(b)
	} else if finger != "" {
		msg(hwnd, "Select the CA file as well", 0x10)
		return
	} else if old, e := load(); e == nil && old.Server == base {
		c.CA = old.CA
	}
	if code == "" {
		old, e := load()
		if e != nil || old.Server != base {
			msg(hwnd, "Enter a new pairing code from Devices in NEXUS", 0x10)
			return
		}
		c = old
		c.GPU = gpu
	}
	if code != "" && exists(configPath()) {
		if msg(hwnd, "Re-pair this computer? The previous credential for the selected device will be revoked by the server.", 0x24) != 6 {
			return
		}
	}
	finishing = true
	uc("EnableWindow", installBtn, 0)
	text(statusBox, "Connecting securely...")
	go func() {
		e := doInstall(c, code)
		r := outcome{ok: e == nil}
		if e != nil {
			r.message = e.Error()
		} else {
			r.message = "Installed. Telemetry starts now and at Windows sign-in."
		}
		results <- r
		uc("PostMessageW", hwnd, wmResult, 0, 0)
	}()
}
func doInstall(c Config, code string) error {
	if e := os.MkdirAll(dir(), 0700); e != nil {
		return e
	}
	if e := copySelf(installed()); e != nil {
		return e
	}
	if code != "" {
		h, e := client(c)
		if e != nil {
			return e
		}
		p, e := pair(h, c.Server, code)
		if e != nil {
			return e
		}
		c.Token, e = dpapi([]byte(p.Token), false)
		if e != nil {
			return e
		}
		c.ID = p.ID
	}
	if e := save(c); e != nil {
		return e
	}
	if e := register(); e != nil {
		return e
	}
	_ = os.Remove(filepath.Join(dir(), "paused"))
	return start(installed(), "--monitor")
}
func uninstall() {
	if finishing {
		return
	}
	if msg(hwnd, "Remove the native NEXUS agent and its local credential? Server history and device profile will remain. Revoke the device in NEXUS to invalidate the server token.", 0x24) != 6 {
		return
	}
	if e := unregister(); e != nil {
		msg(hwnd, e.Error(), 0x10)
		return
	}
	if e := os.Remove(configPath()); e != nil && !os.IsNotExist(e) {
		msg(hwnd, e.Error(), 0x10)
		return
	}
	for _, n := range []string{"paused", "status.txt"} {
		_ = os.Remove(filepath.Join(dir(), n))
	}
	src, e := os.Executable()
	if e != nil {
		msg(hwnd, e.Error(), 0x10)
		return
	}
	f, e := os.CreateTemp("", "nexus-cleanup-*.exe")
	if e != nil {
		msg(hwnd, e.Error(), 0x10)
		return
	}
	p := f.Name()
	f.Close()
	b, e := os.ReadFile(src)
	if e == nil {
		e = os.WriteFile(p, b, 0600)
	}
	if e == nil {
		e = start(p, "--cleanup", strconv.Itoa(os.Getpid()))
	}
	if e != nil {
		msg(hwnd, "Registration removed, but executable cleanup failed: "+e.Error(), 0x10)
		return
	}
	uc("DestroyWindow", hwnd)
}
func cleanup() {
	if len(os.Args) != 3 {
		return
	}
	pid, e := strconv.Atoi(os.Args[2])
	if e != nil || pid <= 0 {
		return
	}
	h := call(k32, "OpenProcess", 0x100000, 0, uintptr(pid))
	if h != 0 {
		call(k32, "WaitForSingleObject", h, 20000)
		call(k32, "CloseHandle", h)
	}
	if !exists(configPath()) {
		for i := 0; i < 40; i++ {
			e := os.Remove(installed())
			if e == nil || os.IsNotExist(e) {
				break
			}
			time.Sleep(time.Second)
		}
		_ = os.Remove(filepath.Join(dir(), "status.txt"))
		_ = os.Remove(filepath.Join(dir(), "paused"))
		_ = os.Remove(dir())
	}
	src, _ := os.Executable()
	call(k32, "MoveFileExW", ptr(w(src)), 0, 4)
}
func wnd(h uintptr, m uint32, wp, lp uintptr) uintptr {
	switch m {
	case wmCommand:
		if monitoring {
			return 0
		}
		switch wp & 0xffff {
		case 101:
			install()
		case 102:
			browse()
		case 103:
			if exists(configPath()) {
				_ = os.WriteFile(filepath.Join(dir(), "paused"), []byte("1"), 0600)
				showStatus()
			}
		case 104:
			_ = os.Remove(filepath.Join(dir(), "paused"))
			if exists(configPath()) {
				_ = start(installed(), "--monitor")
			}
			showStatus()
		case 105:
			uninstall()
		case 106:
			if c, e := load(); e == nil {
				call(shell, "ShellExecuteW", h, ptr(w("open")), ptr(w(c.Server)), 0, 0, 1)
			}
		case 107:
			showStatus()
		}
		return 0
	case wmTimer:
		if monitoring && !exists(configPath()) {
			uc("DestroyWindow", h)
		} else if !monitoring && !finishing {
			showStatus()
		}
		return 0
	case wmResult:
		r := <-results
		finishing = false
		uc("EnableWindow", installBtn, 1)
		text(codeBox, "")
		text(statusBox, r.message)
		if r.ok {
			msg(hwnd, r.message, 0x40)
		} else {
			msg(hwnd, r.message, 0x10)
		}
		return 0
	case wmTray:
		if monitoring && (lp == 0x203 || lp == 0x205) {
			_ = start(installed())
			return 0
		}
	case wmClose:
		if finishing {
			return 0
		}
		uc("DestroyWindow", h)
		return 0
	case wmDestroy:
		if monitoring {
			call(shell, "Shell_NotifyIconW", 2, uintptr(unsafe.Pointer(&tray)))
		}
		uc("PostQuitMessage", 0)
		return 0
	}
	return uc("DefWindowProcW", h, uintptr(m), wp, lp)
}
func main() {
	runtime.LockOSThread()
	if len(os.Args) > 1 && os.Args[1] == "--cleanup" {
		cleanup()
		return
	}
	monitoring = len(os.Args) > 1 && os.Args[1] == "--monitor"
	if os.Getenv("LOCALAPPDATA") == "" {
		msg(0, "LOCALAPPDATA unavailable", 0x10)
		return
	}
	if monitoring {
		sum := sha256.Sum256([]byte(strings.ToLower(dir())))
		r, _, e := k32.NewProc("CreateMutexW").Call(0, 0, ptr(w(`Local\NexusAgent-`+hex.EncodeToString(sum[:8]))))
		if r == 0 || e == syscall.Errno(183) {
			return
		}
		defer call(k32, "CloseHandle", r)
		if !exists(configPath()) {
			return
		}
	}
	instance = call(k32, "GetModuleHandleW", 0)
	class := w("NexusNativeAgentWindow")
	wc := wndclass{Size: uint32(unsafe.Sizeof(wndclass{})), Proc: wndproc, Instance: instance, Icon: uc("LoadIconW", 0, 32512), Cursor: uc("LoadCursorW", 0, 32512), Background: 6, Class: class}
	if uc("RegisterClassExW", uintptr(unsafe.Pointer(&wc))) == 0 {
		return
	}
	hwnd = uc("CreateWindowExW", 0, ptr(class), ptr(w("NEXUS Agent 3.0.1")), 0x00CA0000, 0x80000000, 0x80000000, 610, 510, 0, 0, instance, 0)
	if hwnd == 0 {
		return
	}
	if monitoring {
		initTray(hwnd)
		go monitor()
	} else {
		label("NEXUS | Connect and monitor your computer", 18, 14, 550)
		label("Server HTTPS address", 18, 46, 550)
		c, _ := load()
		base := c.Server
		if base == "" {
			base = ""
		}
		serverBox = edit(base, 18, 68, 552, 0, false)
		label("One-time pairing code (leave blank to repair existing connection)", 18, 104, 552)
		codeBox = edit("", 18, 126, 552, 0, true)
		label("Optional CA certificate (only if Windows does not already trust NEXUS)", 18, 162, 560)
		caBox = edit("", 18, 184, 448, 0, false)
		btn("Browse...", 476, 182, 94, 102)
		label("CA SHA-256 fingerprint from trusted server (required with CA file)", 18, 220, 560)
		fpBox = edit("", 18, 242, 552, 0, false)
		gpuBox = child("BUTTON", "Collect NVIDIA GPU metrics if supported", 0x10003, 18, 280, 550, 26, 0)
		if c.GPU || c.Server == "" {
			uc("SendMessageW", gpuBox, 0xF1, 1, 0)
		}
		installBtn = btn("Install / Repair", 18, 318, 174, 101)
		btn("Pause", 202, 318, 82, 103)
		btn("Resume", 294, 318, 82, 104)
		btn("Open NEXUS", 386, 318, 184, 106)
		btn("Refresh status", 18, 362, 174, 107)
		btn("Uninstall", 386, 362, 184, 105)
		statusBox = child("STATIC", "", 0, 18, 407, 552, 48, 0)
		showStatus()
		uc("ShowWindow", hwnd, 5)
		uc("UpdateWindow", hwnd)
		if len(os.Args) > 1 && os.Args[1] == "--uninstall" {
			uninstall()
		}
	}
	uc("SetTimer", hwnd, 1, 3000, 0)
	var m message
	for {
		r := uc("GetMessageW", uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		uc("TranslateMessage", uintptr(unsafe.Pointer(&m)))
		uc("DispatchMessageW", uintptr(unsafe.Pointer(&m)))
	}
}
