package mcl_cpp

import "fmt"

// NewAeonExecUnit is holds threshold signature keys of either BLS or GLOW type
func NewAeonExecUnit(keyType string, generator string, keys DKGKeyInformation, qual IntVector) BaseAeon {
	switch keyType {
	case GetBLS_AEON():
		return NewBlsAeon(generator, keys, qual)
	case GetGLOW_AEON():
		return NewGlowAeon(generator, keys, qual)
	default:
		panic(fmt.Errorf("Unknown type %v", keyType))
	}
}
