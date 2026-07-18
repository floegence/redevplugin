package runtimeclient

import "github.com/floegence/redevplugin/pkg/runtimetarget"

type targetWire struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

func targetToWire(target runtimetarget.Target) (targetWire, error) {
	if err := runtimetarget.Validate(target); err != nil {
		return targetWire{}, err
	}
	return targetWire{OS: target.OS(), Arch: target.Arch()}, nil
}

func targetFromWire(wire targetWire) (runtimetarget.Target, error) {
	return runtimetarget.FromParts(wire.OS, wire.Arch)
}
