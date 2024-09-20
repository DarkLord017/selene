package consensus_core

import (
	"crypto/sha256"
	"errors"
)

type Forks struct {
	Genesis   ForkVersion
	Altair    ForkVersion
	Bellatrix ForkVersion
	Capella   ForkVersion
	Deneb     ForkVersion
}

type ForkVersion struct {
	Epoch       uint64
	ForkVersion [4]byte
}

func ComputeCommitteeSignRoot(header, forkDataRoot Bytes32) Bytes32 {
	domainType := [4]byte{7, 0, 0, 0}
	domain := ComputeDomain(domainType, forkDataRoot)
	return ComputeSigningRoot(header, domain)
}

func CalculateForkVersion(forks *Forks, slot uint64) [4]byte {
	epoch := slot / 32

	switch {
	case epoch >= forks.Deneb.Epoch:
		return forks.Deneb.ForkVersion
	case epoch >= forks.Capella.Epoch:
		return forks.Capella.ForkVersion
	case epoch >= forks.Bellatrix.Epoch:
		return forks.Bellatrix.ForkVersion
	case epoch >= forks.Altair.Epoch:
		return forks.Altair.ForkVersion
	default:
		return forks.Genesis.ForkVersion
	}
}

func ComputeForkDataRoot(currentVersion [4]byte, genesisValidatorRoot Bytes32) Bytes32 {
	forkData := ForkData{
		CurrentVersion:       currentVersion,
		GenesisValidatorRoot: genesisValidatorRoot,
	}
	return forkData.TreeHashRoot()
}

// GetParticipatingKeys retrieves the participating public keys from the committee based on the bitfield represented as a byte array.
func GetParticipatingKeys(committee *SyncComittee, bitfield [64]byte) ([]BLSPubKey, error) {
	var pks []BLSPubKey
	numBits := len(bitfield) * 8 // Total number of bits

	if len(committee.pubkeys) > numBits {
		return nil, errors.New("bitfield is too short for the number of public keys")
	}

	for i := 0; i < len(bitfield); i++ {
		byteVal := bitfield[i]
		for bit := 0; bit < 8; bit++ {
			if (byteVal & (1 << bit)) != 0 {
				index := i*8 + bit
				if index >= len(committee.pubkeys) {
					break
				}
				pks = append(pks, committee.pubkeys[index])
			}
		}
	}

	return pks, nil
}

func ComputeSigningRoot(objectRoot, domain Bytes32) Bytes32 {
	signingData := SigningData{
		ObjectRoot: objectRoot,
		Domain:     domain,
	}
	return signingData.TreeHashRoot()
}

func ComputeDomain(domainType [4]byte, forkDataRoot Bytes32) Bytes32 {
	data := append(domainType[:], forkDataRoot[:28]...)
	return sha256.Sum256(data)
}

type SigningData struct {
	ObjectRoot Bytes32
	Domain     Bytes32
}

type ForkData struct {
	CurrentVersion       [4]byte
	GenesisValidatorRoot Bytes32
}
