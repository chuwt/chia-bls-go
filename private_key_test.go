package bls

import (
	"fmt"
	"testing"
)

func Test0BytesTruncatingProblem(t *testing.T) {
	testMnemonic := "blood floor grow axis carbon ladder hybrid clutch flight satoshi fork main"
	privateKey := KeyGenWithMnemonic(testMnemonic, "")

	testCases := []struct {
		index       uint32
		expectedHex string
	}{
		{
			index:       26,
			expectedHex: "0x00cbe82fbff4b214b54ca763f012bd4a74824ccf8dd64186c5651216ebfc711f",
		},
		{
			index:       239,
			expectedHex: "0x00f235cdd3c56397dda0e6d808be09e0121653ff74944a33f4cfc11174dfa600",
		},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Valid case with index %v", testCase.index), func(it *testing.T) {
			derivedKey := DerivePathUnhardened(privateKey, []uint32{12381, 8444, 2, testCase.index, 0})
			keyHex := derivedKey.Hex()
			if keyHex != testCase.expectedHex {
				it.Fatalf("Expected %v, got %v", testCase.expectedHex, keyHex)
			}
		})
	}
}
