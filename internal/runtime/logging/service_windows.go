//go:build windows

package logging

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// isWindowsService reports whether the current process is running as a Windows
// service. It tries three approaches in order:
//  1. svc.IsWindowsService: checks whether the direct parent is services.exe.
//  2. hasServiceSID: checks the process token for the well-known Service SID
//     (S-1-5-6), which is inherited by children of SCM-started processes.
//  3. hasServiceAncestor: walks the full ancestor chain looking for services.exe,
//     covering cases where the launcher sits between the SCM and this process
//     and does not pass through the token unmodified.
func isWindowsService() bool {
	if ok, err := svc.IsWindowsService(); err == nil && ok {
		return true
	}
	if hasServiceSID() {
		return true
	}
	return hasServiceAncestor()
}

func hasServiceSID() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	serviceSID, err := windows.CreateWellKnownSid(windows.WELL_KNOWN_SID_TYPE(windows.WinServiceSid))
	if err != nil {
		return false
	}

	ok, err := token.IsMember(serviceSID)
	return err == nil && ok
}

// hasServiceAncestor takes a snapshot of all running processes and walks the
// ancestor chain of the current process. It returns true if any ancestor is
// named services.exe.
func hasServiceAncestor() bool {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snapshot)

	type procInfo struct {
		parentPID uint32
		name      string
	}

	procs := make(map[uint32]procInfo)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		procs[entry.ProcessID] = procInfo{
			parentPID: entry.ParentProcessID,
			name:      windows.UTF16ToString(entry.ExeFile[:]),
		}
	}

	visited := make(map[uint32]bool)
	for pid := uint32(os.Getpid()); ; {
		if visited[pid] {
			break
		}
		visited[pid] = true

		info, ok := procs[pid]
		if !ok {
			break
		}
		if strings.EqualFold(info.name, "services.exe") {
			return true
		}
		pid = info.parentPID
	}
	return false
}
