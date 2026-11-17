// Package backup creates and restores a portable snapshot of kai's state.
// Target data is never committed to git; this is the off-repo safety copy.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Options controls what goes into the archive.
type Options struct {
	Out            string
	DataDir        string
	DistDir        string
	IncludeSession bool
	IncludeRepos   bool
}

// Create writes <root>/kai-backup-<ts>.tar.gz containing data/ and dist/.
func Create(root string, opts Options) (string, error) {
	out := opts.Out
	if out == "" {
		out = filepath.Join(root, fmt.Sprintf("kai-backup-%s.tar.gz", time.Now().UTC().Format("20060102T150405Z")))
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return "", err
	}
	f, err := os.Create(out)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir = filepath.Join(root, "data")
	}
	distDir := opts.DistDir
	if distDir == "" {
		distDir = filepath.Join(root, "dist")
	}
	for _, part := range []struct{ label, dir string }{{"data", dataDir}, {"dist", distDir}} {
		base := part.dir
		if _, err := os.Stat(base); os.IsNotExist(err) {
			continue
		}
		err = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return err
			}
			relToBase, err := filepath.Rel(base, path)
			if err != nil {
				return err
			}
			rel := part.label
			if relToBase != "." {
				rel = filepath.Join(part.label, relToBase)
			}
			if !skipPath(rel, opts) {
				h, err := tar.FileInfoHeader(info, "")
				if err != nil {
					return err
				}
				h.Name = filepath.ToSlash(rel)
				if info.IsDir() {
					h.Name += "/"
				}
				if err := tw.WriteHeader(h); err != nil {
					return err
				}
				if !info.IsDir() {
					src, err := os.Open(path)
					if err != nil {
						return err
					}
					_, copyErr := io.Copy(tw, src)
					src.Close()
					if copyErr != nil {
						return copyErr
					}
				}
			}
			if info.IsDir() {
				return nil
			}
			return nil
		})
		if err != nil {
			tw.Close()
			gz.Close()
			return "", err
		}
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return out, nil
}

func skipPath(rel string, opts Options) bool {
	clean := filepath.ToSlash(rel)
	if !opts.IncludeSession && strings.HasSuffix(clean, "/session.json") {
		return true
	}
	if !opts.IncludeRepos && strings.Contains(clean, "/repos/") {
		return true
	}
	return false
}

// Restore extracts an archive into dest, refusing paths that escape it.
func Restore(archive, dest string) (int, error) {
	f, err := os.Open(archive)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}
		name := filepath.Clean(filepath.FromSlash(h.Name))
		if name == "." || filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
			return count, fmt.Errorf("unsafe path in backup: %s", h.Name)
		}
		target := filepath.Join(dest, name)
		if h.FileInfo().IsDir() || strings.HasSuffix(h.Name, "/") {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return count, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return count, err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return count, err
		}
		_, copyErr := io.Copy(out, tr)
		out.Close()
		if copyErr != nil {
			return count, copyErr
		}
		count++
	}
	return count, nil
}
