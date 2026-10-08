package mcp

import "os/exec"

func ConfigureProcess(cmd *exec.Cmd)  { configureProcess(cmd) }
func KillProcess(cmd *exec.Cmd) error { return killProcess(cmd) }
