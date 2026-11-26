package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testEntry = "0123456789abcdef01234567"

func TestBuildPanelURL(t *testing.T) {
	for _, tc := range []struct {
		name, listen, discovered, wantHost string
		wantDiscovery                      bool
	}{
		{"IPv4 loopback", "127.0.0.2", "", "127.0.0.2", false},
		{"IPv6 loopback", "::1", "", "[::1]", false},
		{"mapped loopback", "::ffff:127.0.0.1", "", "[::ffff:127.0.0.1]", false},
		{"explicit IPv4", "192.0.2.4", "", "192.0.2.4", false},
		{"explicit IPv6", "2001:db8::4", "", "[2001:db8::4]", false},
		{"scoped IPv6", "fe80::1%eth0", "", "[fe80::1%25eth0]", false},
		{"localhost", "localhost", "", "localhost", false},
		{"empty bind", "", "192.0.2.8", "192.0.2.8", true},
		{"IPv4 wildcard", "0.0.0.0", "192.0.2.8", "192.0.2.8", true},
		{"discovered IPv6", "0.0.0.0", "2001:db8::8", "[2001:db8::8]", true},
		{"IPv6 wildcard", "::", "2001:db8::8", "[2001:db8::8]", true},
		{"IPv4 fallback", "0.0.0.0", "", "127.0.0.1", true},
		{"IPv6 fallback", "0:0:0:0:0:0:0:0", "", "[::1]", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got := buildPanelURL(tc.listen, 12345, "/"+testEntry, func() string {
				calls++
				return tc.discovered
			})
			want := "http://" + tc.wantHost + ":12345/" + testEntry + "/"
			wantCalls := 0
			if tc.wantDiscovery {
				wantCalls = 1
			}
			if got != want || calls != wantCalls {
				t.Fatalf("URL = %q, discovery calls = %d; want %q, %d", got, calls, want, wantCalls)
			}
		})
	}
}

func TestPrintPanel(t *testing.T) {
	const token = "0123456789abcdeffedcba9876543210" // test fixture only
	const address = "http://[::1]:12345/" + testEntry + "/"
	path := filepath.Join(t.TempDir(), "panel.json")
	t.Setenv("NFT_FORWARD_CONF", path)

	for _, tc := range []struct {
		name, token, want string
		withToken         bool
		status            int
	}{
		{"URL only", token, address + "\n", false, 0},
		{"URL without token configured", "", address + "\n", false, 0},
		{"labeled info", token, "面板地址: " + address + "\n访问令牌: " + token + "\n", true, 0},
		{"info requires token", "", "", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := fmt.Sprintf(`{"listen":"::1","port":12345,"entry_path":"/%s/","token":%q}`, testEntry, tc.token)
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			var out, stderr bytes.Buffer
			status := printPanel(&out, &stderr, func() string {
				t.Fatal("must not discover a network address for a loopback listen")
				return ""
			}, tc.withToken)
			if status != tc.status || out.String() != tc.want {
				t.Fatalf("status = %d, output = %q; want %d, %q", status, &out, tc.status, tc.want)
			}
			if (status == 0) != (stderr.Len() == 0) || strings.Contains(stderr.String(), token) {
				t.Fatalf("unexpected stderr: %q", &stderr)
			}
		})
	}
}

func TestRunInstalledMenu(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nft-forward.sh")
	var out, stderr bytes.Buffer
	if status, handled := runInstalledMenu(path, nil, &out, &stderr); status != 0 || handled {
		t.Fatalf("missing script: status=%d handled=%v, want standalone fallback", status, handled)
	}
	script := "#!/bin/sh\n[ \"$#\" = 0 ] || exit 99\nread -r choice\nprintf 'choice=%s\\n' \"$choice\"\necho diagnostic >&2\nexit 23\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	status, handled := runInstalledMenu(path, strings.NewReader("0\n"), &out, &stderr)
	if status != 23 || !handled || out.String() != "choice=0\n" || stderr.String() != "diagnostic\n" {
		t.Fatalf("delegated menu: status=%d handled=%v stdout=%q stderr=%q", status, handled, &out, &stderr)
	}
}
