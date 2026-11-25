package packages

import (
	"io"
	"testing"
)

func TestBuiltinPackagesAndMatching(t *testing.T) {
	mgr, err := NewManager()
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	pkgs := mgr.ListPackages()
	if len(pkgs) < 4 {
		t.Fatalf("expected at least 4 built-in packages, got %d", len(pkgs))
	}

	cases := []struct {
		rawArch string
		osID    string
		wantID  string
	}{
		{"x86_64", "centos", "builtin-x86_64-static"},
		{"amd64", "ubuntu", "builtin-x86_64-static"},
		{"aarch64", "openeuler", "builtin-aarch64-static"},
		{"arm64", "kylin", "builtin-aarch64-static"},
		{"armv7l", "debian", "builtin-armhf-static"},
		{"i686", "alpine", "builtin-x86-static"},
	}

	for _, tc := range cases {
		matched := mgr.MatchPackage(tc.rawArch, tc.osID)
		if matched == nil {
			t.Fatalf("MatchPackage(%s, %s) returned nil", tc.rawArch, tc.osID)
		}
		if matched.ID != tc.wantID {
			t.Errorf("MatchPackage(%s, %s) = %s, want %s", tc.rawArch, tc.osID, matched.ID, tc.wantID)
		}

		// Verify embedded binary decompresses cleanly and starts with ELF magic
		rc, _, err := mgr.OpenPackage(matched.ID)
		if err != nil {
			t.Fatalf("OpenPackage(%s) failed: %v", matched.ID, err)
		}
		hdr := make([]byte, 4)
		_, err = io.ReadFull(rc, hdr)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read header of %s failed: %v", matched.ID, err)
		}
		if hdr[0] != 0x7f || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F' {
			t.Errorf("package %s is not a valid ELF binary: %x", matched.ID, hdr)
		}
	}
}
