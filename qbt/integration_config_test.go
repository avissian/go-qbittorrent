//go:build integration

package qbt_test

import (
	"os"
	"strings"
)

// integrationCfg is the single place to edit credentials and test data before running
// integration tests. Environment variables override these defaults when set.
//
// Run: go test -tags=integration -v ./qbt
//
// Optional environment variables:
//
//	QBT_INTEGRATION_URL            - Web UI base URL (trailing slash optional)
//	QBT_INTEGRATION_USER           - username
//	QBT_INTEGRATION_PASSWORD       - password
//	QBT_INTEGRATION_TORRENT_HASH   - lowercase info-hash for Torrents filter tests (may be empty)
var integrationCfg = struct {
	BaseURL           string
	Username          string
	Password          string
	SampleTorrentHash string
}{
	BaseURL:           "http://127.0.0.1:8080/",
	Username:          "admin",
	Password:          "adminadmin",
	SampleTorrentHash: "",
}

func init() {
	if v := os.Getenv("QBT_INTEGRATION_URL"); v != "" {
		integrationCfg.BaseURL = v
	}
	if v := os.Getenv("QBT_INTEGRATION_USER"); v != "" {
		integrationCfg.Username = v
	}
	if v := os.Getenv("QBT_INTEGRATION_PASSWORD"); v != "" {
		integrationCfg.Password = v
	}
	if v := os.Getenv("QBT_INTEGRATION_TORRENT_HASH"); v != "" {
		integrationCfg.SampleTorrentHash = strings.TrimSpace(strings.ToLower(v))
	}
}
