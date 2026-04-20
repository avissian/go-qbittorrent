// Example program: connect to a local qBittorrent Web UI, log in, and print basic session info.
//
// Configure the constants below, then run from the module root:
//
//	go run ./example
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/avissian/go-qbittorrent/qbt"
)

// Set these to match Tools - Preferences - Web UI in the desktop app.
const (
	baseURL  = "http://127.0.0.1:8080/"
	username = "admin"
	password = "adminadmin"
)

func main() {
	log.SetFlags(0)

	client := qbt.NewClient(baseURL)
	if err := client.Login(qbt.LoginOptions{Username: username, Password: password}); err != nil {
		log.Fatalf("login: %v", err)
	}

	appVer, err := client.ApplicationVersion()
	if err != nil {
		log.Fatalf("application version: %v", err)
	}
	apiVer, err := client.WebAPIVersion()
	if err != nil {
		log.Fatalf("web API version: %v", err)
	}
	fmt.Printf("qBittorrent %s (Web API %s)\n", appVer, apiVer)

	torrents, err := client.Torrents(qbt.TorrentsOptions{})
	if err != nil {
		log.Fatalf("list torrents: %v", err)
	}
	fmt.Printf("Torrents returned: %d\n", len(torrents))
	if len(torrents) > 0 {
		b, err := json.MarshalIndent(torrents[0], "", "  ")
		if err != nil {
			log.Fatalf("encode: %v", err)
		}
		if _, err := os.Stdout.Write(append(b, '\n')); err != nil {
			log.Fatalf("write: %v", err)
		}
	}

	// Uncomment to add a torrent from a magnet link or HTTP URL to your session.
	// err = client.DownloadLinks(
	// 	[]string{"magnet:?xt=urn:btih:..."},
	// 	qbt.DownloadOptions{},
	// )
	// if err != nil {
	// 	log.Fatalf("add torrent: %v", err)
	// }
}
