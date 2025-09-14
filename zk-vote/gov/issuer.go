package gov

import (
	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/kysee/zkp/utils"
)

var (
	totalCitizens          []*Citizen
	merkleCitizens         *merkletree.Tree
	MerkleCitizensBytes    []byte
	MerkleCitizensRootHash []byte
)

func RegisterCitizen(c *Citizen) int {
	totalCitizens = append(totalCitizens, c)

	d := c.HashDIDPubKey()

	if merkleCitizens == nil {
		merkleCitizens = merkletree.New(utils.DefaultHasher())
	}
	merkleCitizens.Push(d)
	MerkleCitizensBytes = append(MerkleCitizensBytes, d...)
	MerkleCitizensRootHash = merkleCitizens.Root()

	return len(totalCitizens)
}

func GetCitizenIdx(c *Citizen) int {
	for i, _c := range totalCitizens {
		if c.SN == _c.SN {
			return i
		}
	}
	return -1
}
