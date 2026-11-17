package backup

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateAndRestore(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("data/demo/assets.json", `{"hosts":1}`)
	write("data/demo/session.json", `SECRET`)
	write("dist/demo_1.zip", "zipdata")

	out, err := Create(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	n, err := Restore(out, dest)
	if err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("restored %d files", n)
	}
	if _, err := os.Stat(filepath.Join(dest, "data/demo/assets.json")); err != nil {
		t.Error("state missing after restore")
	}
	if _, err := os.Stat(filepath.Join(dest, "data/demo/session.json")); err == nil {
		t.Error("session.json should be excluded by default")
	}
}

func TestRestoreRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "bad.tar.gz")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeTarGz(f, "../escape.txt", "nope"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Restore(archive, t.TempDir()); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("traversal not rejected: %v", err)
	}
}

func writeTarGz(f *os.File, name, body string) error {
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body))}); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, body); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
