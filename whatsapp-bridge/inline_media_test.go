package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInlineMediaFile(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("png-bytes"))
	p, dir, err := inlineMediaFile(b64, "../../etc/shadow/Screen Shot 1.png")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if filepath.Dir(p) != dir || !strings.HasSuffix(p, "Screen_Shot_1.png") {
		t.Fatalf("name not confined/sanitized: %s", p)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("temp dir mode %v", fi.Mode().Perm())
	}
	if got, _ := os.ReadFile(p); string(got) != "png-bytes" {
		t.Fatalf("content %q", got)
	}
	for _, c := range []struct{ b64, name string }{
		{"!!!", "a.png"}, {"", "a.png"}, {b64, "noext"}, {b64, ".."}, {b64, ""},
	} {
		if _, d, err := inlineMediaFile(c.b64, c.name); err == nil {
			os.RemoveAll(d)
			t.Errorf("accepted b64=%q name=%q", c.b64, c.name)
		}
	}
}
