package winservice

import (
	"errors"
	"regexp"
	"time"
)

const BootstrapTrustFile = "bootstrap-trust.json"

var setupNonce = regexp.MustCompile(`^[a-f0-9]{32}$`)

type BootstrapTrust struct {
	Version     int    `json:"version"`
	Product     string `json:"product"`
	Purpose     string `json:"purpose"`
	Nonce       string `json:"nonce"`
	SHA256      string `json:"sha256"`
	CreatedUnix int64  `json:"created_unix"`
	ExpiresUnix int64  `json:"expires_unix"`
}

func (t BootstrapTrust) Validate(nonce string, now time.Time) error {
	if t.Version != 1 || t.Product != "LuminaVPN" || t.Purpose != "service-bootstrap" || !setupNonce.MatchString(nonce) || t.Nonce != nonce || !digestText.MatchString(t.SHA256) || t.CreatedUnix <= 0 || t.ExpiresUnix-t.CreatedUnix != 1800 || now.Unix() < t.CreatedUnix || now.Unix() >= t.ExpiresUnix {
		return errors.New("trusted fresh bootstrap envelope required")
	}
	return nil
}
