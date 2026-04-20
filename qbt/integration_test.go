//go:build integration

package qbt_test

import (
	"strings"
	"testing"

	"github.com/avissian/go-qbittorrent/qbt"
)

func TestIntegration_Login(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests with -short")
	}
	t.Parallel()
	client := qbt.NewClient(integrationCfg.BaseURL)
	err := client.Login(qbt.LoginOptions{
		Username: integrationCfg.Username,
		Password: integrationCfg.Password,
	})
	if err != nil {
		t.Skipf("integration: Login: %v", err)
	}
	if !client.Authenticated {
		t.Fatal("expected Authenticated to be true after successful Login")
	}
}

func TestIntegration_AppVersions(t *testing.T) {
	t.Parallel()
	client := integrationClient(t)

	ver, err := client.ApplicationVersion()
	if err != nil {
		t.Fatalf("ApplicationVersion: %v", err)
	}
	if strings.TrimSpace(ver) == "" {
		t.Fatal("ApplicationVersion: empty string")
	}

	apiVer, err := client.WebAPIVersion()
	if err != nil {
		t.Fatalf("WebAPIVersion: %v", err)
	}
	if strings.TrimSpace(apiVer) == "" {
		t.Fatal("WebAPIVersion: empty string")
	}

	bi, err := client.BuildInfo()
	if err != nil {
		t.Fatalf("BuildInfo: %v", err)
	}
	if bi.LibtorrentVersion == "" {
		t.Fatal("BuildInfo: expected non-empty libtorrent version")
	}
}

func TestIntegration_TransferInfo(t *testing.T) {
	t.Parallel()
	client := integrationClient(t)

	info, err := client.Info(qbt.InfoOptions{})
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	// Connection status is always present in a healthy session response.
	if info.ConnectionStatus == "" {
		t.Fatal("Info: empty ConnectionStatus")
	}
}

func TestIntegration_Torrents(t *testing.T) {
	t.Parallel()
	client := integrationClient(t)

	opts := qbt.TorrentsOptions{}
	if h := integrationCfg.SampleTorrentHash; h != "" {
		opts.Hashes = []string{h}
	}

	list, err := client.Torrents(opts)
	if err != nil {
		t.Fatalf("Torrents: %v", err)
	}
	if integrationCfg.SampleTorrentHash != "" && len(list) > 0 {
		if !strings.EqualFold(list[0].Hash, integrationCfg.SampleTorrentHash) {
			t.Fatalf("Torrents: hash mismatch: got %q want %q", list[0].Hash, integrationCfg.SampleTorrentHash)
		}
	}
}

func TestIntegration_PreferencesRead(t *testing.T) {
	t.Parallel()
	client := integrationClient(t)

	_, err := client.Preferences()
	if err != nil {
		t.Fatalf("Preferences: %v", err)
	}
}

// integrationClient logs in once per test; on failure skips (no local qBittorrent).
func integrationClient(t *testing.T) *qbt.Client {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration tests with -short")
	}
	client := qbt.NewClient(integrationCfg.BaseURL)
	err := client.Login(qbt.LoginOptions{
		Username: integrationCfg.Username,
		Password: integrationCfg.Password,
	})
	if err != nil {
		t.Skipf("integration: login failed (is qBittorrent running with matching credentials?): %v", err)
	}
	return client
}
