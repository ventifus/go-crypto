// +build amd64,!gccgo,!appengine

package fp

import (
	"math/big"
	"testing"
)

func (e Elt) toBig() *big.Int {
	var x [Size]byte
	for i := range e {
		x[i] = e[Size-i-1]
	}
	var b big.Int
	b.SetBytes(x[:])
	return &b
}

func TestFp(t *testing.T) {
	const numTests = 256
	var F = Fp255()
	var x, y, z Elt
	var zz big.Int

	p := P.toBig()

	t.Run("Add", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			F.Rand(&x)
			F.Rand(&y)
			F.Add(&z, &x, &y)
			F.Modp(&z)

			xx, yy := x.toBig(), y.toBig()
			zz.Add(xx, yy).Mod(&zz, p)

			if zz.Cmp(z.toBig()) != 0 {
				t.Errorf("error on add\nwant: 0x%s\n got: %s", zz.Text(16), z)
			}
		}
	})
	t.Run("Sub", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			F.Rand(&x)
			F.Rand(&y)
			F.Sub(&z, &x, &y)
			F.Modp(&z)

			xx, yy := x.toBig(), y.toBig()
			zz.Sub(xx, yy).Mod(&zz, p)

			if zz.Cmp(z.toBig()) != 0 {
				t.Errorf("error on sub\nwant: 0x%s\n got: %s", zz.Text(16), z)
			}
		}
	})
	t.Run("Mul", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			F.Rand(&x)
			F.Rand(&y)
			F.Mul(&z, &x, &y)
			F.Modp(&z)

			xx, yy := x.toBig(), y.toBig()
			zz.Mul(xx, yy).Mod(&zz, p)

			if zz.Cmp(z.toBig()) != 0 {
				t.Errorf("error on mul\nwant: 0x%s\n got: %s", zz.Text(16), z)
			}
		}
	})
	t.Run("Sqr", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			F.Rand(&x)
			F.Sqr(&z, &x)
			F.Modp(&z)

			xx := x.toBig()
			zz.Mul(xx, xx).Mod(&zz, p)

			if zz.Cmp(z.toBig()) != 0 {
				t.Errorf("error on sqr\nwant: 0x%s\n got: %s", zz.Text(16), z)
			}
		}
	})
	t.Run("Inv", func(t *testing.T) {
		for i := 0; i < numTests; i++ {
			F.Rand(&x)
			F.Inv(&z, &x)
			F.Modp(&z)

			xx := x.toBig()
			zz.ModInverse(xx, p)

			if zz.Cmp(z.toBig()) != 0 {
				t.Errorf("error on inv\nwant: 0x%s\n got: %s", zz.Text(16), z)
			}
		}
	})
}

func BenchmarkAdd(b *testing.B) {
	var F = Fp255()
	var x, y, z Elt
	F.Rand(&x)
	F.Rand(&y)
	F.Rand(&z)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		F.Add(&x, &y, &z)
	}
}

func BenchmarkSub(b *testing.B) {
	var F = Fp255()
	var x, y, z Elt
	F.Rand(&x)
	F.Rand(&y)
	F.Rand(&z)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		F.Sub(&x, &y, &z)
	}
}

func BenchmarkMul(b *testing.B) {
	var F = Fp255()
	var x, y, z Elt
	F.Rand(&x)
	F.Rand(&y)
	F.Rand(&z)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		F.Mul(&x, &y, &z)
	}
}

func BenchmarkSqr(b *testing.B) {
	var F = Fp255()
	var x, y Elt
	F.Rand(&x)
	F.Rand(&y)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		F.Sqr(&x, &y)
	}
}

func BenchmarkInv(b *testing.B) {
	var F = Fp255()
	var x, y Elt
	F.Rand(&x)
	F.Rand(&y)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		F.Inv(&x, &y)
	}
}
