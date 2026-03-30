package main

import (
	"strings"
	"testing"

	"github.com/drogers0/gh-image/internal/upload"
)

// TestCookieFromValue_BasicAttributes verifies the cookie has the expected fields.
func TestCookieFromValue_BasicAttributes(t *testing.T) {
	cookie, err := cookieFromValue("mytoken123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cookie.Name != "user_session" {
		t.Errorf("expected Name 'user_session', got %q", cookie.Name)
	}
	if cookie.Value != "mytoken123" {
		t.Errorf("expected Value 'mytoken123', got %q", cookie.Value)
	}
	if cookie.Domain != "github.com" {
		t.Errorf("expected Domain 'github.com', got %q", cookie.Domain)
	}
	if cookie.Path != "/" {
		t.Errorf("expected Path '/', got %q", cookie.Path)
	}
	if !cookie.Secure {
		t.Error("expected Secure to be true")
	}
	if !cookie.HttpOnly {
		t.Error("expected HttpOnly to be true")
	}
}

// TestCookieFromValue_TrimsWhitespace verifies leading/trailing whitespace is stripped.
func TestCookieFromValue_TrimsWhitespace(t *testing.T) {
	cookie, err := cookieFromValue("  token_with_spaces  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cookie.Value != "token_with_spaces" {
		t.Errorf("expected whitespace trimmed, got %q", cookie.Value)
	}
}

// TestCookieFromValue_RejectsEmpty verifies that empty/whitespace-only values error.
func TestCookieFromValue_RejectsEmpty(t *testing.T) {
	tests := []string{"", "   ", "\t\n"}
	for _, v := range tests {
		_, err := cookieFromValue(v)
		if err == nil {
			t.Errorf("expected error for empty token %q, got nil", v)
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("unexpected error message for %q: %v", v, err)
		}
	}
}

// TestResolveSessionCookie_FlagPriority verifies --token flag takes highest priority.
func TestResolveSessionCookie_FlagPriority(t *testing.T) {
	t.Setenv("GH_SESSION_TOKEN", "env_token")
	cookie, err := resolveSessionCookie("flag_token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cookie.Value != "flag_token" {
		t.Errorf("expected flag_token to win, got %q", cookie.Value)
	}
}

// TestResolveSessionCookie_EnvFallback verifies GH_SESSION_TOKEN is used when no flag.
func TestResolveSessionCookie_EnvFallback(t *testing.T) {
	t.Setenv("GH_SESSION_TOKEN", "env_token_value")
	cookie, err := resolveSessionCookie("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cookie.Value != "env_token_value" {
		t.Errorf("expected env_token_value, got %q", cookie.Value)
	}
}

// TestResolveSessionCookie_BrowserFallbackError verifies browser error is wrapped correctly.
func TestResolveSessionCookie_BrowserFallbackError(t *testing.T) {
	// No flag, no env var: should fall through to browser extraction which
	// will fail in CI (no browser). Confirm the error message contains guidance.
	t.Setenv("GH_SESSION_TOKEN", "")
	_, err := resolveSessionCookie("")
	if err == nil {
		// Only expected to fail when not in a browser environment
		t.Skip("browser cookies found; skipping browser-error test")
	}
	if !strings.Contains(err.Error(), "no session token found") {
		t.Errorf("expected 'no session token found' in error, got: %v", err)
	}
}

// TestCookieFromValue_UsableByNewClient verifies the cookie produced by
// cookieFromValue can be passed to upload.NewClient.
func TestCookieFromValue_UsableByNewClient(t *testing.T) {
	cookie, err := cookieFromValue("testtoken")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	client := upload.NewClient(cookie)
	if client == nil {
		t.Fatal("expected upload.NewClient to return a non-nil client")
	}
}

func TestClassifySubcommand(t *testing.T) {
	tests := []struct {
		name                    string
		imagePaths              []string
		firstPosAfterDoubleDash bool
		tokenFlag               string
		wantSubcommand          string
		wantErrContains         string
	}{
		{
			name:           "extract-token selected",
			imagePaths:     []string{"extract-token"},
			wantSubcommand: "extract-token",
		},
		{
			name:           "check-token selected",
			imagePaths:     []string{"check-token"},
			wantSubcommand: "check-token",
		},
		{
			name:                    "double-dash treats check-token as filename",
			imagePaths:              []string{"check-token"},
			firstPosAfterDoubleDash: true,
			wantSubcommand:          "",
		},
		{
			name:                    "double-dash treats extract-token as filename",
			imagePaths:              []string{"extract-token"},
			firstPosAfterDoubleDash: true,
			wantSubcommand:          "",
		},
		{
			name:            "extract-token with extra args errors",
			imagePaths:      []string{"extract-token", "extra"},
			wantErrContains: "does not take positional arguments",
		},
		{
			name:            "check-token with extra args errors",
			imagePaths:      []string{"check-token", "extra"},
			wantErrContains: "does not take positional arguments",
		},
		{
			name:            "extract-token with token flag errors",
			imagePaths:      []string{"extract-token"},
			tokenFlag:       "abc123",
			wantErrContains: "--token cannot be combined",
		},
		{
			name:           "non-subcommand remains upload mode",
			imagePaths:     []string{"image.png"},
			wantSubcommand: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotSubcommand, err := classifySubcommand(tc.imagePaths, tc.firstPosAfterDoubleDash, tc.tokenFlag)
			if tc.wantErrContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrContains)
				}
				if !strings.Contains(err.Error(), tc.wantErrContains) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrContains, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotSubcommand != tc.wantSubcommand {
				t.Fatalf("expected subcommand %q, got %q", tc.wantSubcommand, gotSubcommand)
			}
		})
	}
}
