// Package backup writes and restores an encrypted snapshot of the whole
// Rakhsh config: the state file and every generated tunnel config. The archive
// is AES-256-GCM sealed under a key derived from your passphrase with argon2id,
// so a stolen backup file is useless without it.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

const magic = "RKHBAK1\n"

var paths = []string{"/opt/rakhsh/state.json", "/opt/rakhsh/conf"}

func deriveKey(pass string, salt []byte) []byte {
	return argon2.IDKey([]byte(pass), salt, 3, 64*1024, 2, 32)
}

// Create writes an encrypted backup to outPath.
func Create(outPath, pass string) error {
	var tarbuf bytes.Buffer
	gz := gzip.NewWriter(&tarbuf)
	tw := tar.NewWriter(gz)
	for _, p := range paths {
		if err := addPath(tw, p); err != nil {
			return err
		}
	}
	tw.Close()
	gz.Close()

	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	_, _ = rand.Read(salt)
	_, _ = rand.Read(nonce)
	block, err := aes.NewCipher(deriveKey(pass, salt))
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	sealed := aead.Seal(nil, nonce, tarbuf.Bytes(), []byte(magic))

	var out bytes.Buffer
	out.WriteString(magic)
	out.Write(salt)
	out.Write(nonce)
	out.Write(sealed)
	return os.WriteFile(outPath, out.Bytes(), 0o600)
}

func addPath(tw *tar.Writer, root string) error {
	info, err := os.Stat(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return addFile(tw, root, root)
	}
	return filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		return addFile(tw, p, p)
	})
}

func addFile(tw *tar.Writer, name, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b))}); err != nil {
		return err
	}
	_, err = tw.Write(b)
	return err
}

// Restore decrypts inPath and writes files back to their original locations.
func Restore(inPath, pass string) error {
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	if len(raw) < len(magic)+28 || string(raw[:len(magic)]) != magic {
		return fmt.Errorf("not a rakhsh backup")
	}
	off := len(magic)
	salt := raw[off : off+16]
	nonce := raw[off+16 : off+28]
	sealed := raw[off+28:]
	block, err := aes.NewCipher(deriveKey(pass, salt))
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plain, err := aead.Open(nil, nonce, sealed, []byte(magic))
	if err != nil {
		return fmt.Errorf("wrong passphrase or corrupt backup")
	}
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(h.Name), 0o755); err != nil {
			return err
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return err
		}
		if err := os.WriteFile(h.Name, b, 0o600); err != nil {
			return err
		}
	}
	return nil
}
