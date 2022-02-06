//go:build gc && !purego

package hctr2

//go:noescape
func xctrAsm(nr int, xk *uint32, out, in *byte, nblocks int, iv *[BlockSize]byte)
