//go:build !unix

package admin

func withUmask(_ int, f func() error) error { return f() }
