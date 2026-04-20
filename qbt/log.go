package qbt

import (
	"encoding/json"
)

// Logs returns main application log lines (api/v2/log/main).
func (client *Client) Logs(filters map[string]string) (logs []Log, err error) {
	resp, err := client.get("api/v2/log/main", filters)
	if err != nil {
		return logs, err
	}
	err = json.NewDecoder(resp.Body).Decode(&logs)
	return logs, err
}

// PeerLogs returns peer-related log lines (api/v2/log/peers).
func (client *Client) PeerLogs(filters map[string]string) (logs []PeerLog, err error) {
	resp, err := client.get("api/v2/log/peers", filters)
	if err != nil {
		return logs, err
	}
	err = json.NewDecoder(resp.Body).Decode(&logs)
	return logs, err
}
