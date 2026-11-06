// Package usersession protects session blobs in the current Windows user's
// DPAPI scope. Callers impersonating a GUI user must retain that OS-thread
// identity for the entire operation; no SID supplied in a message is trusted.
package usersession

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
)

type Protector interface {
	Protect(plaintext, entropy []byte) ([]byte, error)
	Unprotect(ciphertext, entropy []byte) ([]byte, error)
}

type Envelope struct {
	Version    int    `json:"version"`
	Scope      string `json:"scope"`
	Ciphertext []byte `json:"ciphertext"`
}

func entropy(purpose string) ([]byte, error) {
	if len(purpose) == 0 || len(purpose) > 1024 {
		return nil, errors.New("invalid session protection purpose")
	}
	sum := sha256.Sum256([]byte("NetLaunch/user-session/v1/" + purpose))
	return sum[:], nil
}

func SealWith(p Protector, purpose string, plaintext []byte) (Envelope, error) {
	e, err := entropy(purpose)
	if err != nil || p == nil || len(plaintext) == 0 || len(plaintext) > 256<<10 {
		return Envelope{}, errors.New("invalid protected session")
	}
	b, err := p.Protect(plaintext, e)
	if err != nil || len(b) == 0 || len(b) > 512<<10 {
		clear(b)
		return Envelope{}, errors.New("session encryption failed")
	}
	return Envelope{Version: 1, Scope: "windows-user", Ciphertext: b}, nil
}

func OpenWith(p Protector, purpose string, envelope Envelope) ([]byte, error) {
	e, err := entropy(purpose)
	if err != nil || p == nil || envelope.Version != 1 || envelope.Scope != "windows-user" || len(envelope.Ciphertext) == 0 || len(envelope.Ciphertext) > 512<<10 {
		return nil, errors.New("invalid protected session")
	}
	b, err := p.Unprotect(envelope.Ciphertext, e)
	if err != nil {
		return nil, errors.New("session decryption failed")
	}
	if len(b) == 0 || len(b) > 256<<10 {
		clear(b)
		return nil, errors.New("invalid decrypted session")
	}
	return b, nil
}

func Seal(purpose string, plaintext []byte) (Envelope, error) {
	return SealWith(nativeProtector{}, purpose, plaintext)
}
func Open(purpose string, raw []byte) ([]byte, error) {
	var e Envelope
	if len(raw) > 768<<10 || json.Unmarshal(raw, &e) != nil {
		return nil, errors.New("invalid encrypted session envelope")
	}
	return OpenWith(nativeProtector{}, purpose, e)
}
