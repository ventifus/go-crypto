package cryptobyte

import (
	"bytes"
	"fmt"
	"testing"
)

func builderBytesEq(b *Builder, want ...byte) error {
	got := b.Bytes()
	if !bytes.Equal(got, want) {
		return fmt.Errorf("Bytes() = %v, want %v", got, want)
	}
	return nil
}

func TestBytes(t *testing.T) {
	b := NewBuilder(nil)
	v := []byte("foobarbaz")
	b.AddBytes(v[0:3])
	b.AddBytes(v[3:4])
	b.AddBytes(v[4:9])
	if err := builderBytesEq(b, v...); err != nil {
		t.Error(err)
	}
	s := String(b.Bytes())
	for _, w := range []string{"foo", "bar", "baz"} {
		var got []byte
		if !s.GetBytes(&got, 3) {
			t.Errorf("GetBytes() = false, want true (w = %v)", w)
		}
		want := []byte(w)
		if !bytes.Equal(got, want) {
			t.Errorf("GetBytes(): got = %v, want %v", got, want)
		}
	}
	if len(s) != 0 {
		t.Errorf("len(s) = %d, want 0", len(s))
	}
}

func TestU8(t *testing.T) {
	b := NewBuilder(nil)
	b.AddU8(42)
	if err := builderBytesEq(b, 42); err != nil {
		t.Error(err)
	}

	var s String = b.Bytes()
	var v uint8
	if !s.GetU8(&v) {
		t.Error("GetU8() = false, want true")
	}
	if v != 42 {
		t.Errorf("v = %d, want 42", v)
	}
	if len(s) != 0 {
		t.Errorf("len(s) = %d, want 0", len(s))
	}
}

func TestU16(t *testing.T) {
	b := NewBuilder(nil)
	b.AddU16(65534)
	if err := builderBytesEq(b, 255, 254); err != nil {
		t.Error(err)
	}
	var s String = b.Bytes()
	var v uint16
	if !s.GetU16(&v) {
		t.Error("GetU16() == false, want true")
	}
	if v != 65534 {
		t.Errorf("v = %d, want 65534", v)
	}
	if len(s) != 0 {
		t.Errorf("len(s) = %d, want 0", len(s))
	}
}

func TestU24(t *testing.T) {
	b := NewBuilder(nil)
	b.AddU24(0xfffefd)
	if err := builderBytesEq(b, 255, 254, 253); err != nil {
		t.Error(err)
	}

	var s String = b.Bytes()
	var v uint32
	if !s.GetU24(&v) {
		t.Error("GetU8() = false, want true")
	}
	if v != 0xfffefd {
		t.Errorf("v = %d, want fffefd", v)
	}
	if len(s) != 0 {
		t.Errorf("len(s) = %d, want 0", len(s))
	}
}

func TestU24Truncation(t *testing.T) {
	b := NewBuilder(nil)
	b.AddU24(0x10111213)
	if err := builderBytesEq(b, 0x11, 0x12, 0x13); err != nil {
		t.Error(err)
	}
}

func TestU32(t *testing.T) {
	b := NewBuilder(nil)
	b.AddU32(0xfffefdfc)
	if err := builderBytesEq(b, 255, 254, 253, 252); err != nil {
		t.Error(err)
	}

	var s String = b.Bytes()
	var v uint32
	if !s.GetU32(&v) {
		t.Error("GetU8() = false, want true")
	}
	if v != 0xfffefdfc {
		t.Errorf("v = %x, want fffefdfc", v)
	}
	if len(s) != 0 {
		t.Errorf("len(s) = %d, want 0", len(s))
	}
}

func TestUMultiple(t *testing.T) {
	b := NewBuilder(nil)
	b.AddU8(23)
	b.AddU32(0xfffefdfc)
	b.AddU16(42)
	if err := builderBytesEq(b, 23, 255, 254, 253, 252, 0, 42); err != nil {
		t.Error(err)
	}

	var s String = b.Bytes()
	var (
		x uint8
		y uint32
		z uint16
	)
	if !s.GetU8(&x) || !s.GetU32(&y) || !s.GetU16(&z) {
		t.Error("GetU8() = false, want true")
	}
	if x != 23 || y != 0xfffefdfc || z != 42 {
		t.Errorf("x, y, z = %d, %d, %d; want 23, 4294901244, 5")
	}
	if len(s) != 0 {
		t.Errorf("len(s) = %d, want 0", len(s))
	}
}

func TestU8LengthPrefixedSimple(t *testing.T) {
	b := NewBuilder(nil)
	b.AddU8LengthPrefixed(func(c *Builder) {
		c.AddU8(23)
		c.AddU8(42)
	})
	if err := builderBytesEq(b, 2, 23, 42); err != nil {
		t.Error(err)
	}

	var base, child String = b.Bytes(), nil
	var x, y uint8
	if !base.GetU8LengthPrefixed(&child) || !child.GetU8(&x) ||
		!child.GetU8(&y) {
		t.Error("parsing failed")
	}
	if x != 23 || y != 42 {
		t.Errorf("want x, y == 23, 42; got %d, %d", x, y)
	}
	if len(base) != 0 {
		fmt.Errorf("len(base) = %d, want 0", len(base))
	}
	if len(child) != 0 {
		fmt.Errorf("len(child) = %d, want 0", len(child))
	}
}

func TestU8LengthPrefixedMulti(t *testing.T) {
	b := NewBuilder(nil)
	b.AddU8LengthPrefixed(func(c *Builder) {
		c.AddU8(23)
		c.AddU8(42)
	})
	b.AddU8(5)
	b.AddU8LengthPrefixed(func(c *Builder) {
		c.AddU8(123)
		c.AddU8(234)
	})
	if err := builderBytesEq(b, 2, 23, 42, 5, 2, 123, 234); err != nil {
		t.Error(err)
	}

	var s, child String = b.Bytes(), nil
	var u, v, w, x, y uint8
	if !s.GetU8LengthPrefixed(&child) || !child.GetU8(&u) || !child.GetU8(&v) ||
		!s.GetU8(&w) || !s.GetU8LengthPrefixed(&child) || !child.GetU8(&x) || !child.GetU8(&y) {
		t.Error("parsing failed")
	}
	if u != 23 || v != 42 || w != 5 || x != 123 || y != 234 {
		t.Errorf("u, v, w, x, y = %d, %d, %d, %d, %d; want 23, 42, 5, 123, 234",
			u, v, w, x, y)
	}
	if len(s) != 0 {
		t.Errorf("len(s) = %d, want 0", len(s))
	}
	if len(child) != 0 {
		t.Errorf("len(child) = %d, want 0", len(child))
	}
}

func TestU8LengthPrefixedNested(t *testing.T) {
	b := NewBuilder(nil)
	b.AddU8LengthPrefixed(func(c *Builder) {
		c.AddU8(5)
		c.AddU8LengthPrefixed(func(d *Builder) {
			d.AddU8(23)
			d.AddU8(42)
		})
		c.AddU8(123)
	})
	if err := builderBytesEq(b, 5, 5, 2, 23, 42, 123); err != nil {
		t.Error(err)
	}

	var base, child1, child2 String = b.Bytes(), nil, nil
	var u, v, w, x uint8
	if !base.GetU8LengthPrefixed(&child1) {
		t.Error("parsing base failed")
	}
	if !child1.GetU8(&u) || !child1.GetU8LengthPrefixed(&child2) || !child1.GetU8(&x) {
		t.Error("parsing child1 failed")
	}
	if !child2.GetU8(&v) || !child2.GetU8(&w) {
		t.Error("parsing child2 failed")
	}
	if u != 5 || v != 23 || w != 42 || x != 123 {
		t.Errorf("u, v, w, x = %d, %d, %d, %d, want 5, 23, 42, 123",
			u, v, w, x)
	}
	if len(base) != 0 {
		t.Errorf("len(base) = %d, want 0", len(base))
	}
	if len(child1) != 0 {
		t.Errorf("len(child1) = %d, want 0", len(child1))
	}
	if len(base) != 0 {
		t.Errorf("len(child2) = %d, want 0", len(child2))
	}
}

func TestDiscardChild(t *testing.T) {
	b := NewBuilder(nil)
	b.AddU8(10)
	b.AddU8LengthPrefixed(func(child *Builder) {
		child.AddU8(20)
		b.DiscardPendingChild()
	})
	b.AddU8(30)
	want := []byte{10, 20}
	if bytes.Equal(want, b.Bytes()) {
		t.Errorf("want b.Bytes() == %v, got %v", want, b.Bytes())
	}
}

func TestPreallocatedBuffer(t *testing.T) {
	var buf [5]byte
	b := NewBuilder(buf[0:0])
	b.AddU8(1)
	b.AddU8LengthPrefixed(func(c *Builder) {
		c.AddU8(3)
		c.AddU8(4)
	})
	b.AddU16(1286) // Outgrow buf by one byte.
	want := []byte{1, 2, 3, 4, 0}
	if !bytes.Equal(buf[:], want) {
		t.Errorf("buf = %v want %v", buf, want)
	}
	if err := builderBytesEq(b, 1, 2, 3, 4, 5, 6); err != nil {
		t.Error(err)
	}
}
