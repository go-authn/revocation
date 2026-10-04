// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package main

import (
	"fmt"
	"io/fs"
	"syscall"
)

// checkOwner refuses a directory that belongs to neither euid nor root: its
// owner can replace what is in it whatever its mode says.
func checkOwner(dir string, fi fs.FileInfo, euid int) error {
	owner := fi.Sys().(*syscall.Stat_t).Uid
	if owner != 0 && int64(owner) != int64(euid) {
		return fmt.Errorf("state_dir %s belongs to uid %d, neither this process's uid %d nor root: "+
			"whoever owns it decides which list comes next; chown it", dir, owner, euid)
	}
	return nil
}
