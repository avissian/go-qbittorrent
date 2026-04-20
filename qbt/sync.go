package qbt

import (
	"encoding/json"
	"strconv"

	wrapper "github.com/pkg/errors"
)

// Sync Endpoints
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

// MainData return diff state between Rid (used by WebUI main page)
// @params Rid - 0 for default next
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
