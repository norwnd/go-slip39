package main

import (
	"encoding/hex"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/gavincarr/go-slip39"
)

var seedDerivationPath = []uint32{
	hdkeychain.HardenedKeyStart + 44, // purpose 44' for HD wallets
	hdkeychain.HardenedKeyStart + 60, // eth coin type 60'
	hdkeychain.HardenedKeyStart,      // account 0'
	0,                                // branch 0
	0,                                // index 0
}

func main() {
	// shares correspond to `TODO` secret
	shares := []string{
		"TODO",
		"TODO",
		//"TODO",
	}
	passphrase := ""
	//passphrase := "TREZOR"

	result, err := slip39.CombineMnemonicsWithPassphrase(shares, []byte(passphrase))
	if err != nil {
		panic(err)
	}

	fmt.Println(fmt.Sprintf("%v", result))
	fmt.Println(fmt.Sprintf("%x", result))

	pk := secp256k1.PrivKeyFromBytes(result)
	fmt.Println(fmt.Sprintf("%x", pk.Serialize()))

	extKey, err := GenDeepChild(pk.Serialize(), seedDerivationPath)
	if err != nil {
		panic(err)
	}
	derivedPk, err := extKey.SerializedPrivKey()
	if err != nil {
		panic(err)
	}
	fmt.Println(fmt.Sprintf("%x", derivedPk))
}

func main1() {
	masterSecret := "TODO"
	passphrase := ""
	//passphrase := "TREZOR"

	masterSecretBytes, err := hex.DecodeString(masterSecret)
	if err != nil {
		panic(err)
	}
	groupCount := 1
	memberGroupParams := []slip39.MemberGroupParameters{{2, 3}}
	groups, _ := slip39.GenerateMnemonicsWithPassphrase(
		groupCount,
		memberGroupParams,
		masterSecretBytes,
		[]byte(passphrase),
	)
	if len(groups[0]) != 3 {
		panic("unexpected group size")
	}

	fmt.Println(fmt.Sprintf("%v", groups[0][0]))
	fmt.Println(fmt.Sprintf("%v", groups[0][1]))
	fmt.Println(fmt.Sprintf("%v", groups[0][2]))
}

// GenDeepChild derives the leaf of a path of children from a root extended key.
func GenDeepChild(seed []byte, kids []uint32) (*hdkeychain.ExtendedKey, error) {
	root, err := hdkeychain.NewMaster(seed, &RootKeyParams{})
	if err != nil {
		return nil, err
	}
	defer root.Zero()

	return GenDeepChildFromXPriv(root, kids)
}

// GenDeepChildFromXPriv derives the leaf of a path of children from a parent
// extended key.
func GenDeepChildFromXPriv(root *hdkeychain.ExtendedKey, kids []uint32) (*hdkeychain.ExtendedKey, error) {
	genChild := func(parent *hdkeychain.ExtendedKey, childIdx uint32) (*hdkeychain.ExtendedKey, error) {
		err := hdkeychain.ErrInvalidChild
		for err == hdkeychain.ErrInvalidChild {
			var kid *hdkeychain.ExtendedKey
			kid, err = parent.ChildBIP32Std(childIdx)
			if err == nil {
				return kid, nil
			}
			fmt.Printf("Child derive skipped a key index %d -> %d", childIdx, childIdx+1) // < 1 in 2^127 chance
			childIdx++
		}
		return nil, err
	}

	extKey := root
	for i, childIdx := range kids {
		childExtKey, err := genChild(extKey, childIdx)
		if i > 0 { // don't zero the input arg
			extKey.Zero()
		}
		extKey = childExtKey
		if err != nil {
			return nil, fmt.Errorf("genChild error: %w", err)
		}
	}

	return extKey, nil
}

// RootKeyParams implements hdkeychain.NetworkParams for master
// hdkeychain.ExtendedKey creation.
type RootKeyParams struct{}

func (*RootKeyParams) HDPrivKeyVersion() [4]byte {
	return [4]byte{0x74, 0x61, 0x63, 0x6f} // ASCII "taco"
}
func (*RootKeyParams) HDPubKeyVersion() [4]byte {
	return [4]byte{0x64, 0x65, 0x78, 0x63} // ASCII "dexc"
}
