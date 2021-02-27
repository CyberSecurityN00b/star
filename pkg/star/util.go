package star

import (
	"encoding/hex"
	"math"
	"strings"
)

// SqrtedString turns a []byte into a hexadecimal string that is split into
// substrings demarcated by the specified separator string. The number of
// substrings is equal to the square root of the length of []byte. (Note: If
// "len([]byte)" is not a square number, not all data will be included).
func SqrtedString(b []byte, sep string) string {
	var parts []string
	n := int(math.Sqrt(float64(len(b))))
	for i := 0; i < n; i++ {
		parts = append(parts, strings.ToUpper(hex.EncodeToString(b[i*n:i*n+n])))
	}
	return strings.Join(parts, sep)
}
