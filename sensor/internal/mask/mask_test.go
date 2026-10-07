package mask

import (
	"reflect"
	"strings"
	"testing"
)

func TestTextMasksKnownSecrets(t *testing.T) {
	for _, secret := range []string{
		"AKIAABCDEFGHIJKLMNOP",
		"ghp_" + strings.Repeat("a", 36),
		"sk-proj-" + strings.Repeat("b", 30),
		"sk_sel_" + strings.Repeat("c", 20),
		"eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4",
		"Bearer abcdefghijklmnop",
	} {
		got := Text("curl -H x " + secret + " https://api")
		if strings.Contains(got, secret) {
			t.Errorf("not masked: %s", got)
		}
	}
	if got := Text("https://bob:hunter2@db.example/x"); got != "https://bob:…@db.example/x" {
		t.Error(got)
	}
	if got := Text("ls -la /tmp"); got != "ls -la /tmp" {
		t.Error("harmless text changed:", got)
	}
}

func TestArgvMasksNamedSecrets(t *testing.T) {
	// the Erlang cookie the spike found on the dev box, and friends
	in := []string{"erl", "-setcookie", "45WTPWNN2W", "--password", "x", "--token=abc",
		"DB_PASSWORD=pw", "PATH=/usr/bin", "-v", "--user", "bob"}
	want := []string{"erl", "-setcookie", "…", "--password", "…", "--token=…",
		"DB_PASSWORD=…", "PATH=/usr/bin", "-v", "--user", "bob"}
	if got := Argv(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}
