package beacon

/*
#cgo LDFLAGS: -lmcl -lgmp -lboost_serialization
#cgo CXXFLAGS: -fPIC -g -O2 -std=c++14
*/
import "C"

// Needs to match settings in beacon_setup_service.hpp
type aeonType = BLSAeon

func newAeonExecUnit(generator string, keys DKGKeyInformation, qual IntVector) aeonType {
	return NewBLSAeon(generator, keys, qual)
}

func deleteAeonExecUnit(aeon aeonType) {
	DeleteBLSAeon(aeon)
}
