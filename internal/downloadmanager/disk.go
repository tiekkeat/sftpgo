// Copyright (C) 2026 SFTPGo contributors
// SPDX-License-Identifier: AGPL-3.0-only

package downloadmanager

import "github.com/shirou/gopsutil/v3/disk"

func stagingFree(path string) (int64, error) {
	u, e := disk.Usage(path)
	if e != nil {
		return 0, e
	}
	return int64(u.Free), nil
}
