package bls

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestClient(t *testing.T) {
	address := "xch1f0ryxk6qn096hefcwrdwpuph2hm24w69jnzezhkfswk0z2jar7aq5zzpfj"

	t.Log(toPuzzleHash(address))
}

type RawTransaction struct {
	Additions []Addition `json:"additions"`
	Fee       uint64     `json:"fee"`
}

type Addition struct {
	Amount     string `json:"amount"`
	PuzzleHash string `json:"puzzle_hash"`
}

func createSignedTransaction(tx RawTransaction) error {
	if len(tx.Additions) < 1 {
		return errors.New("no transactions ")
	}
	return nil
}

func toPuzzleHash(address string) ([]byte, error) {
	_, data, err := Decode(address)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, errors.New("Invalid Address ")
	}
	decoded, err := convertbits(data, 5, 8, false)
	if err != nil {
		return nil, err
	}

	decodeBytes := make([]byte, len(decoded))
	for index, d := range decoded {
		decodeBytes[index] = uint8(d)
	}

	return decodeBytes, nil
}

var charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func Decode(bechString string) (string, []int, error) {
	if len(bechString) > 90 {
		return "", nil, fmt.Errorf("too long : len=%d", len(bechString))
	}
	if strings.ToLower(bechString) != bechString && strings.ToUpper(bechString) != bechString {
		return "", nil, fmt.Errorf("mixed case")
	}
	bechString = strings.ToLower(bechString)
	pos := strings.LastIndex(bechString, "1")
	if pos < 1 || pos+7 > len(bechString) {
		return "", nil, fmt.Errorf("separator '1' at invalid position : pos=%d , len=%d", pos, len(bechString))
	}
	hrp := bechString[0:pos]
	for p, c := range hrp {
		if c < 33 || c > 126 {
			return "", nil, fmt.Errorf("invalid character human-readable part : bechString[%d]=%d", p, c)
		}
	}
	var data []int
	for p := pos + 1; p < len(bechString); p++ {
		d := strings.Index(charset, fmt.Sprintf("%c", bechString[p]))
		if d == -1 {
			return "", nil, fmt.Errorf("invalid character data part : bechString[%d]=%d", p, bechString[p])
		}
		data = append(data, d)
	}
	if !verifyChecksum(hrp, data) {
		return "", nil, fmt.Errorf("invalid checksum")
	}
	return hrp, data[:len(data)-6], nil
}

const M = 0x2BC830A3

func convertbits(data []int, frombits, tobits uint, pad bool) ([]int, error) {
	acc := 0
	bits := uint(0)
	var ret []int
	maxv := (1 << tobits) - 1
	for idx, value := range data {
		if value < 0 || (value>>frombits) != 0 {
			return nil, fmt.Errorf("invalid data range : data[%d]=%d (frombits=%d)", idx, value, frombits)
		}
		acc = (acc << frombits) | value
		bits += frombits
		for bits >= tobits {
			bits -= tobits
			ret = append(ret, (acc>>bits)&maxv)
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, (acc<<(tobits-bits))&maxv)
		}
	} else if bits >= frombits {
		return nil, fmt.Errorf("illegal zero padding")
	} else if ((acc << (tobits - bits)) & maxv) != 0 {
		return nil, fmt.Errorf("non-zero padding")
	}
	return ret, nil
}

func verifyChecksum(hrp string, data []int) bool {
	return polymod(append(hrpExpand(hrp), data...)) == M
}

func polymod(values []int) int {
	chk := 1
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

var generator = []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

func hrpExpand(hrp string) []int {
	var ret []int
	for _, c := range hrp {
		ret = append(ret, int(c>>5))
	}
	ret = append(ret, 0)
	for _, c := range hrp {
		ret = append(ret, int(c&31))
	}
	return ret
}
