package qbt

import (
	"encoding/json"
)

// Log Endpoints

// Logs of the qbittorrent client
func (client *Client) Logs(filters map[string]string) (logs []Log, err error) {
	resp, err := client.get("api/v2/log/main", filters)
	if err != nil {
		return logs, err
	}
	err = json.NewDecoder(resp.Body).Decode(&logs)
	return logs, err
}

// PeerLogs of the qbittorrent client
func (client *Client) PeerLogs(filters map[string]string) (logs []PeerLog, err error) {
	resp, err := client.get("api/v2/log/peers", filters)
	if err != nil {
		return logs, err
	}
	err = json.NewDecoder(resp.Body).Decode(&logs)
	return logs, err
}
