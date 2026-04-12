package cookies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/pbkdf2"
)

// GetGitHubSession returns the user_session cookie for github.com
// from the Helium browser. Reads only this one specific cookie.
func GetGitHubSession() (*http.Cookie, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("getting config dir: %w", err)
	}
	cookiePath := filepath.Join(cfgDir, "net.imput.helium", "Default", "Cookies")
	if _, err := os.Stat(cookiePath); err != nil {
		return nil, fmt.Errorf("helium cookie file not found at %s", cookiePath)
	}

	tmp, err := os.CreateTemp("", "helium-cookies-*.db")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	data, err := os.ReadFile(cookiePath)
	if err != nil {
		return nil, fmt.Errorf("reading cookie file: %w", err)
	}
	if err := os.WriteFile(tmp.Name(), data, 0600); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("opening cookie db: %w", err)
	}
	defer db.Close()

	row := db.QueryRow(
		`SELECT host_key, encrypted_value, path, expires_utc, is_secure, is_httponly
		 FROM cookies
		 WHERE host_key IN ('github.com', '.github.com') AND name = 'user_session'
		 LIMIT 1`,
	)

	var hostKey string
	var encryptedValue []byte
	var cookiePath2 string
	var expiresUTC int64
	var isSecure, isHTTPOnly int
	if err := row.Scan(&hostKey, &encryptedValue, &cookiePath2, &expiresUTC, &isSecure, &isHTTPOnly); err != nil {
		return nil, fmt.Errorf("no github.com user_session cookie found in Helium — are you logged in? (%w)", err)
	}

	value, err := tryDecrypt(encryptedValue, hostKey)
	if err != nil {
		return nil, fmt.Errorf("decrypting cookie: %w", err)
	}

	expires := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(expiresUTC) * time.Microsecond)

	return &http.Cookie{
		Name:     "user_session",
		Value:    value,
		Domain:   "github.com",
		Path:     cookiePath2,
		Expires:  expires,
		Secure:   isSecure == 1,
		HttpOnly: isHTTPOnly == 1,
	}, nil
}

func tryDecrypt(encrypted []byte, hostKey string) (string, error) {
	for _, pw := range candidatePasswords() {
		val, err := decryptCookie(encrypted, pw, hostKey)
		if err != nil {
			continue
		}
		if isValidToken(val) {
			return val, nil
		}
	}
	return "", fmt.Errorf("could not decrypt with any candidate key")
}

func candidatePasswords() [][]byte {
	var candidates [][]byte
	for _, svc := range []string{"Helium Storage Key", "Helium Safe Storage", "Chromium Safe Storage", "Chrome Safe Storage"} {
		out, err := exec.Command(
			"/usr/bin/security", "find-generic-password",
			"-s", svc, "-w",
		).Output()
		if err == nil {
			candidates = append(candidates, []byte(strings.TrimSpace(string(out))))
		}
	}
	candidates = append(candidates, []byte("peanuts"))
	return candidates
}

func isValidToken(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func decryptCookie(encrypted, password []byte, hostKey string) (string, error) {
	if len(encrypted) == 0 {
		return "", nil
	}
	if len(encrypted) < 3 || string(encrypted[:3]) != "v10" {
		return string(encrypted), nil
	}
	encrypted = encrypted[3:]

	key := pbkdf2.Key(password, []byte("saltysalt"), 1003, 16, sha1.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(encrypted) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = ' '
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encrypted))
	mode.CryptBlocks(decrypted, encrypted)

	if len(decrypted) > 0 {
		pad := int(decrypted[len(decrypted)-1])
		if pad > 0 && pad <= aes.BlockSize && pad <= len(decrypted) {
			decrypted = decrypted[:len(decrypted)-pad]
		}
	}

	// Chromium db version ≥24: plaintext prefixed with SHA256(host_key)
	if len(decrypted) > 32 {
		expected := sha256.Sum256([]byte(hostKey))
		match := true
		for i := 0; i < 32; i++ {
			if decrypted[i] != expected[i] {
				match = false
				break
			}
		}
		if match {
			decrypted = decrypted[32:]
		}
	}

	return string(decrypted), nil
}
