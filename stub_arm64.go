//go:build gc && !purego

package hctr2

//go:noescape
func xctrAsm(nr int, xk *uint32, out, in *byte, nblocks int, iv *[BlockSize]byte)

// useMultiBlock causes cmd/asm to define "const_useMultiBlock"
// in "go_asm.h", which instructs xctrAsm to compute multiple
// blocks at a time.
//
// Commenting out or deleting this constant restricts xctrAsm
// to just one block a a time.
//
//lint:ignore U1000 used by xctr_asm64.s.
const useMultiBlock = true
