package hctr2

const haveAsm = false

//go:noescape
func polyvalAsm(z, x, y *fieldElement)

//go:noescape
func polyvalAsm2(z, x, y *fieldElement)
