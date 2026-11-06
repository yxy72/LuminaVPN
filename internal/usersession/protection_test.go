package usersession

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"testing"
)

type fakeProtector struct{ user string }

func (p fakeProtector) aead(e []byte) cipher.AEAD {
	key := sha256.Sum256(append([]byte(p.user), e...))
	b, _ := aes.NewCipher(key[:])
	g, _ := cipher.NewGCM(b)
	return g
}
func (p fakeProtector) Protect(b, e []byte) ([]byte, error) {
	g := p.aead(e)
	return g.Seal(nil, make([]byte, g.NonceSize()), b, e), nil
}
func (p fakeProtector) Unprotect(b, e []byte) ([]byte, error) {
	g := p.aead(e)
	return g.Open(nil, make([]byte, g.NonceSize()), b, e)
}
func TestProtectionRequiresSameUserPurposeAndUntamperedEnvelope(t *testing.T) {
	p := fakeProtector{"user-A"}
	plain := []byte(`{"cookie":"retained-session","created":"fixed"}`)
	e, err := SealWith(p, "profile-A", plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(e.Ciphertext, []byte("retained-session")) {
		t.Fatal("plaintext leaked")
	}
	b, err := OpenWith(p, "profile-A", e)
	if err != nil || !bytes.Equal(b, plain) {
		t.Fatal(err)
	}
	if _, err = OpenWith(fakeProtector{"user-B"}, "profile-A", e); err == nil {
		t.Fatal("another user decrypted")
	}
	if _, err = OpenWith(p, "profile-B", e); err == nil {
		t.Fatal("another purpose decrypted")
	}
	e.Ciphertext[0] ^= 1
	if _, err = OpenWith(p, "profile-A", e); err == nil {
		t.Fatal("tampered envelope accepted")
	}
}
func TestProtectionRejectsPlaintextAndUnboundedShapes(t *testing.T) {
	if _, e := OpenWith(fakeProtector{"A"}, "x", Envelope{}); e == nil {
		t.Fatal("plaintext accepted")
	}
	if _, e := SealWith(fakeProtector{"A"}, "", []byte("x")); e == nil {
		t.Fatal("missing purpose accepted")
	}
	if _, e := SealWith(fakeProtector{"A"}, "x", make([]byte, 256<<10+1)); e == nil {
		t.Fatal("oversize accepted")
	}
}
