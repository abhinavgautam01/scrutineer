//go:build !windows

package worker

import "syscall"

const sourceReadFlags = syscall.O_NONBLOCK
