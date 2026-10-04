// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix

package main

import "io/fs"

// checkOwner accepts any owner where fs.FileInfo reports none the way Unix
// does (Windows: ACLs decide). Restrict the directory to revokd's account
// yourself.
func checkOwner(string, fs.FileInfo, int) error { return nil }
