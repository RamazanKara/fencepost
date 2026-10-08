package mcp

import (
	"os/exec"
	"syscall"
)

func configureProcess(cmd *exec.Cmd)  { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }
func killProcess(cmd *exec.Cmd) error { return cmd.Process.Kill() }
