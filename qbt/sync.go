package qbt

import (
	"encoding/json"
	"strconv"

	wrapper "github.com/pkg/errors"
)

// TorrentPeers returns peer list state for sync (api/v2/sync/torrentPeers).
func (client *Client) TorrentPeers(hash string, rid uint64) (peers TorrentPeers, err error) {
	if rid == 0 {
		rid = client.Rid
	}
	opts := map[string]string{
		"hash": hash,
		"rid":  strconv.FormatUint(rid, 10),
	}
	resp, err := client.get("api/v2/sync/torrentPeers", opts)
	if err != nil {
		return
	}
	if sc := (*resp).StatusCode; sc != 200 {
		err = wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
		return
	}

	err = json.NewDecoder(resp.Body).Decode(&peers)
	if err != nil {
		return
	}
	client.Rid = peers.Rid
	return

}

// MainData returns incremental main-view state (api/v2/sync/maindata). Use rid 0 to continue from client.Rid.
func (client *Client) MainData(rid uint64) (sync Sync, err error) {
	if rid == 0 {
		rid = client.Rid
	}
	opts := map[string]string{
		"rid": strconv.FormatUint(rid, 10),
	}
	resp, err := client.get("api/v2/sync/maindata", opts)
	if err != nil {
		return
	}
	if sc := (*resp).StatusCode; sc != 200 {
		err = wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
		return
	}
	err = json.NewDecoder(resp.Body).Decode(&sync)
	if err != nil {
		return
	}
	client.Rid = sync.Rid
	return
}
