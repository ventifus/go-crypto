// +build amd64,!gccgo,!appengine

package fp_test

import (
	"crypto/rand"
	"golang.org/x/crypto/curve25519/internal/fp"
	"math/big"
	"testing"
)

func toBig(e fp.Elt) *big.Int {
	var x [fp.Size]byte
	for i := range e {
		x[i] = e[fp.Size-i-1]
	}
	var b big.Int
	b.SetBytes(x[:])
	return &b
}

func TestFp(t *testing.T) {
	const numTests = 256
	var x, y, z fp.Elt
	var zz big.Int

	p := toBig(fp.P)

	t.Run("Add", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			_, _ = rand.Read(y[:])
			fp.Add(&z, &x, &y)
			fp.Modp(&z)

			xx, yy := toBig(x), toBig(y)
			zz.Add(xx, yy).Mod(&zz, p)

			if zz.Cmp(toBig(z)) != 0 {
				t.Errorf("error on add\nwant: 0x%s\n got: %s", zz.Text(16), z)
			}
		}
	})
	t.Run("Sub", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			_, _ = rand.Read(y[:])
			fp.Sub(&z, &x, &y)
			fp.Modp(&z)

			xx, yy := toBig(x), toBig(y)
			zz.Sub(xx, yy).Mod(&zz, p)

			if zz.Cmp(toBig(z)) != 0 {
				t.Errorf("error on sub\nwant: 0x%s\n got: %s", zz.Text(16), z)
			}
		}
	})
	t.Run("Mul", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			_, _ = rand.Read(y[:])
			fp.Mul(&z, &x, &y)
			fp.Modp(&z)

			xx, yy := toBig(x), toBig(y)
			zz.Mul(xx, yy).Mod(&zz, p)

			if zz.Cmp(toBig(z)) != 0 {
				t.Errorf("error on mul\nwant: 0x%s\n got: %s", zz.Text(16), z)
			}
		}
	})
	t.Run("Sqr", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			fp.Sqr(&z, &x)
			fp.Modp(&z)

			xx := toBig(x)
			zz.Mul(xx, xx).Mod(&zz, p)

			if zz.Cmp(toBig(z)) != 0 {
				t.Errorf("error on sqr\nwant: 0x%s\n got: %s", zz.Text(16), z)
			}
		}
	})
	t.Run("Mula24", func(t *testing.T) {
		a24 := big.NewInt(121666)
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			fp.MulA24(&z, &x)
			fp.Modp(&z)

			xx := toBig(x)
			zz.Mul(xx, a24).Mod(&zz, p)

			if zz.Cmp(toBig(z)) != 0 {
				t.Errorf("error on mula24\nwant: 0x%s\n got: %s", zz.Text(16), z)
			}
		}
	})
	t.Run("Inv", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			_, _ = rand.Read(x[:])
			fp.Inv(&z, &x)
			fp.Modp(&z)

			xx := toBig(x)
			zz.ModInverse(xx, p)

			if zz.Cmp(toBig(z)) != 0 {
				t.Errorf("error on inv\nwant: 0x%s\n got: %s", zz.Text(16), z)
			}
		}
	})
}

func BenchmarkFp(b *testing.B) {
	var x, y, z fp.Elt
	_, _ = rand.Read(x[:])
	_, _ = rand.Read(y[:])
	_, _ = rand.Read(z[:])
	b.ResetTimer()
	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp.Add(&x, &y, &z)
		}
	})
	b.Run("Sub", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp.Sub(&x, &y, &z)
		}
	})
	b.Run("Mul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp.Mul(&x, &y, &z)
		}
	})
	b.Run("Sqr", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp.Sqr(&x, &y)
		}
	})
	b.Run("Inv", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			fp.Inv(&x, &y)
		}
	})
}
