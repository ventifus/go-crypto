package subtle

import "crypto/subtle"

// ConstantTimeCompare returns 1 if the two slices, x and y, have equal contents
// and 0 otherwise. The time taken is a function of the length of the slices and
// is independent of the contents.
func ConstantTimeCompare(x, y []byte) int {
	return subtle.ConstantTimeCompare(x, y)
}
