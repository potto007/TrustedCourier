//go:build !unix

package unixsocket

func withUmask(_ int, f func() error) error { return f() }
