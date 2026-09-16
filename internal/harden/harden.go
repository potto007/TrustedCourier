// Package harden applies process hardening to a process that holds
// plaintext Secrets. The plugin SDK has an identical copy in
// sdk/plugin/internal/harden: the two modules release independently, and
// the SDK's public surface stays the Backend interface (ADR-0004).
package harden

// DisableCoreDumps keeps the process from ever writing a core dump. On
// every unix platform the core file size limit becomes zero, hard and
// soft, so the process cannot raise it again. On Linux the process is also
// marked not dumpable, which keeps other users' processes from reading its
// memory through ptrace or /proc.
func DisableCoreDumps() error { return disableCoreDumps() }
