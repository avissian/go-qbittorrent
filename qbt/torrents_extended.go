package qbt

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"

	wrapper "github.com/pkg/errors"
)

// TorrentsCount returns the number of torrents in the session (api/v2/torrents/count).
func (client *Client) TorrentsCount() (int, error) {
	resp, err := client.get("api/v2/torrents/count", nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 {
		return 0, wrapper.Errorf("torrents/count: status %v: %s", resp.StatusCode, string(body))
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil {
		return 0, wrapper.Wrap(err, "parse torrent count")
	}
	return n, nil
}

// TorrentPieceAvailability returns per-piece peer availability counts (api/v2/torrents/pieceAvailability).
func (client *Client) TorrentPieceAvailability(hash string) ([]int, error) {
	resp, err := client.get("api/v2/torrents/pieceAvailability", map[string]string{"hash": strings.ToLower(hash)})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out []int
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// AddWebSeeds adds HTTP(S) seeds to a torrent (api/v2/torrents/addWebSeeds).
func (client *Client) AddWebSeeds(hash string, urls []string) error {
	opts := map[string]string{
		"hash": strings.ToLower(hash),
		"urls": delimit(urls, "|"),
	}
	resp, err := client.post("api/v2/torrents/addWebSeeds", opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("addWebSeeds: status %v: %s", sc, string(body))
	}
}

// EditWebSeed replaces one web seed URL with another (api/v2/torrents/editWebSeed).
func (client *Client) EditWebSeed(hash, origURL, newURL string) error {
	opts := map[string]string{
		"hash":    strings.ToLower(hash),
		"origUrl": origURL,
		"newUrl":  newURL,
	}
	resp, err := client.post("api/v2/torrents/editWebSeed", opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("editWebSeed: status %v: %s", sc, string(body))
	}
}

// RemoveWebSeeds removes web seeds from a torrent (api/v2/torrents/removeWebSeeds).
func (client *Client) RemoveWebSeeds(hash string, urls []string) error {
	opts := map[string]string{
		"hash": strings.ToLower(hash),
		"urls": delimit(urls, "|"),
	}
	resp, err := client.post("api/v2/torrents/removeWebSeeds", opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("removeWebSeeds: status %v: %s", sc, string(body))
	}
}

// AddPeers attempts to connect to peers for the given torrents (api/v2/torrents/addPeers).
func (client *Client) AddPeers(hashes []string, peers []string) (map[string]AddPeersResult, error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"peers":  delimit(peers, "|"),
	}
	resp, err := client.post("api/v2/torrents/addPeers", opts)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, wrapper.Errorf("addPeers: status %v: %s", resp.StatusCode, string(body))
	}
	var out map[string]AddPeersResult
	err = json.Unmarshal(body, &out)
	return out, err
}

// SetTorrentSavePath sets the torrent content path when Auto TMM is disabled (api/v2/torrents/setSavePath). id is the torrent hash/id.
func (client *Client) SetTorrentSavePath(ids []string, savePath string) error {
	opts := map[string]string{
		"id":   delimit(ids, "|"),
		"path": savePath,
	}
	resp, err := client.post("api/v2/torrents/setSavePath", opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("setSavePath: status %v: %s", sc, string(body))
	}
}

// SetTorrentDownloadPath sets the incomplete-download path when Auto TMM is disabled (api/v2/torrents/setDownloadPath).
func (client *Client) SetTorrentDownloadPath(ids []string, downloadPath string) error {
	opts := map[string]string{
		"id":   delimit(ids, "|"),
		"path": downloadPath,
	}
	resp, err := client.post("api/v2/torrents/setDownloadPath", opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("setDownloadPath: status %v: %s", sc, string(body))
	}
}

// SetTorrentComment sets the comment for one or more torrents (api/v2/torrents/setComment).
func (client *Client) SetTorrentComment(hashes []string, comment string) error {
	opts := map[string]string{
		"hashes":  delimit(hashes, "|"),
		"comment": comment,
	}
	resp, err := client.post("api/v2/torrents/setComment", opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("setComment: status %v: %s", sc, string(body))
	}
}

// SetTorrentTags replaces the full tag set for torrents (api/v2/torrents/setTags).
func (client *Client) SetTorrentTags(hashes []string, tags []string) error {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"tags":   delimit(tags, ","),
	}
	resp, err := client.post("api/v2/torrents/setTags", opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("setTags: status %v: %s", sc, string(body))
	}
}

// RenameTorrentFile renames a file inside a torrent (api/v2/torrents/renameFile).
func (client *Client) RenameTorrentFile(hash, oldPath, newPath string) error {
	opts := map[string]string{
		"hash":    strings.ToLower(hash),
		"oldPath": oldPath,
		"newPath": newPath,
	}
	resp, err := client.post("api/v2/torrents/renameFile", opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("renameFile: status %v: %s", sc, string(body))
	}
}

// RenameTorrentFolder renames a folder inside a torrent (api/v2/torrents/renameFolder).
func (client *Client) RenameTorrentFolder(hash, oldPath, newPath string) error {
	opts := map[string]string{
		"hash":    strings.ToLower(hash),
		"oldPath": oldPath,
		"newPath": newPath,
	}
	resp, err := client.post("api/v2/torrents/renameFolder", opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("renameFolder: status %v: %s", sc, string(body))
	}
}

// ExportTorrent returns the .torrent file bytes for a torrent (api/v2/torrents/export).
func (client *Client) ExportTorrent(hash string) ([]byte, error) {
	resp, err := client.post("api/v2/torrents/export", map[string]string{"hash": strings.ToLower(hash)})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, wrapper.Errorf("export: status %v: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// TorrentSSLParameters returns SSL parameters for a torrent (api/v2/torrents/SSLParameters).
func (client *Client) TorrentSSLParameters(hash string) (TorrentSSLParameters, error) {
	var out TorrentSSLParameters
	resp, err := client.get("api/v2/torrents/SSLParameters", map[string]string{"hash": strings.ToLower(hash)})
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}

// SetTorrentSSLParameters sets SSL certificate material for a torrent (api/v2/torrents/setSSLParameters).
func (client *Client) SetTorrentSSLParameters(hash string, p TorrentSSLParameters) error {
	opts := map[string]string{
		"hash":            strings.ToLower(hash),
		"ssl_certificate": p.SSLCertificate,
		"ssl_private_key": p.SSLPrivateKey,
		"ssl_dh_params":   p.SSLDhParams,
	}
	resp, err := client.post("api/v2/torrents/setSSLParameters", opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return wrapper.Errorf("setSSLParameters: status %v: %s", sc, string(body))
	}
}

// FetchTorrentMetadata fetches or resolves torrent metadata by magnet/URL/hash (api/v2/torrents/fetchMetadata).
// On 202 Accepted the metadata is not ready yet; body may contain a placeholder JSON object.
func (client *Client) FetchTorrentMetadata(source string, downloader string) (body []byte, statusCode int, err error) {
	opts := map[string]string{"source": source}
	if downloader != "" {
		opts["downloader"] = downloader
	}
	resp, err := client.post("api/v2/torrents/fetchMetadata", opts)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return b, resp.StatusCode, nil
}

// ParseTorrentMetadata parses local .torrent files and returns serialized metadata (api/v2/torrents/parseMetadata).
func (client *Client) ParseTorrentMetadata(filePaths []string) (json.RawMessage, error) {
	if len(filePaths) == 0 {
		return nil, wrapper.Errorf("at least one torrent file path is required")
	}
	resp, err := client.postMultipartFiles("api/v2/torrents/parseMetadata", filePaths, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, wrapper.Errorf("parseMetadata: status %v: %s", resp.StatusCode, string(b))
	}
	return json.RawMessage(b), nil
}

// SaveTorrentMetadata exports a previously resolved metadata entry to a .torrent buffer (api/v2/torrents/saveMetadata).
func (client *Client) SaveTorrentMetadata(source string) ([]byte, error) {
	resp, err := client.post("api/v2/torrents/saveMetadata", map[string]string{"source": source})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, wrapper.Errorf("saveMetadata: status %v: %s", resp.StatusCode, string(body))
	}
	return body, nil
}
