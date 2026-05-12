package qbt

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	wrapper "github.com/pkg/errors"
)

// Torrents lists torrents (api/v2/torrents/info) according to opts.
func (client *Client) Torrents(opts TorrentsOptions) (torrentList []TorrentInfo, err error) {
	params := map[string]string{}
	if opts.Filter != nil {
		params["filter"] = *opts.Filter
	}
	if opts.Category != nil {
		params["category"] = *opts.Category
	}
	if opts.Sort != nil {
		params["sort"] = *opts.Sort
	}
	if opts.Reverse != nil {
		params["reverse"] = strconv.FormatBool(*opts.Reverse)
	}
	if opts.Offset != nil {
		params["offset"] = strconv.Itoa(*opts.Offset)
	}
	if opts.Limit != nil {
		params["limit"] = strconv.Itoa(*opts.Limit)
	}
	if opts.Hashes != nil {
		params["hashes"] = delimit(opts.Hashes, "%0A")
	}
	resp, err := client.post("api/v2/torrents/info", params)
	if err != nil {
		return torrentList, err
	}
	json.NewDecoder(resp.Body).Decode(&torrentList)
	return torrentList, nil
}

// Torrent returns properties for one torrent (api/v2/torrents/properties).
func (client *Client) Torrent(hash string) (torrent Torrent, err error) {
	var opts = map[string]string{"hash": strings.ToLower(hash)}
	resp, err := client.get("api/v2/torrents/properties", opts)
	if err != nil {
		return torrent, err
	}
	json.NewDecoder(resp.Body).Decode(&torrent)
	return torrent, nil
}

// TorrentTrackers returns trackers for the torrent identified by hash.
func (client *Client) TorrentTrackers(hash string) (trackers []Tracker, err error) {
	var opts = map[string]string{"hash": strings.ToLower(hash)}
	resp, err := client.get("api/v2/torrents/trackers", opts)
	if err != nil {
		return trackers, err
	}
	json.NewDecoder(resp.Body).Decode(&trackers)
	return trackers, nil
}

// TorrentWebSeeds returns HTTP(S) web seeds for the torrent.
func (client *Client) TorrentWebSeeds(hash string) (webSeeds []WebSeed, err error) {
	var opts = map[string]string{"hash": strings.ToLower(hash)}
	resp, err := client.get("api/v2/torrents/webseeds", opts)
	if err != nil {
		return webSeeds, err
	}
	json.NewDecoder(resp.Body).Decode(&webSeeds)
	return webSeeds, nil
}

// TorrentFiles returns files for the torrent (api/v2/torrents/files).
func (client *Client) TorrentFiles(hash string) (files []TorrentFile, err error) {
	var opts = map[string]string{"hash": strings.ToLower(hash)}
	resp, err := client.get("api/v2/torrents/files", opts)
	if err != nil {
		return files, err
	}
	json.NewDecoder(resp.Body).Decode(&files)
	return files, nil
}

// TorrentPieceStates returns per-piece state codes (api/v2/torrents/pieceStates).
func (client *Client) TorrentPieceStates(hash string) (states []int, err error) {
	var opts = map[string]string{"hash": strings.ToLower(hash)}
	resp, err := client.get("api/v2/torrents/pieceStates", opts)
	if err != nil {
		return states, err
	}
	json.NewDecoder(resp.Body).Decode(&states)
	return states, nil
}

// TorrentPieceHashes returns SHA-256 piece hashes (api/v2/torrents/pieceHashes).
func (client *Client) TorrentPieceHashes(hash string) (hashes []string, err error) {
	var opts = map[string]string{"hash": strings.ToLower(hash)}
	resp, err := client.get("api/v2/torrents/pieceHashes", opts)
	if err != nil {
		return hashes, err
	}
	json.NewDecoder(resp.Body).Decode(&hashes)
	return hashes, nil
}

// Pause stops the given torrents (stop/pause depending on API version).
func (client *Client) Pause(hashes []string) (err error) {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	var resp *http.Response
	if client.Version[1] >= '5' {
		resp, err = client.post("api/v2/torrents/stop", opts)
	} else {
		resp, err = client.post("api/v2/torrents/pause", opts)
	}
	if err != nil {
		return err
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// Resume starts the given torrents (start/resume depending on API version).
func (client *Client) Resume(hashes []string) (err error) {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	var resp *http.Response
	if client.Version[1] >= '5' {
		resp, err = client.post("api/v2/torrents/start", opts)
	} else {
		resp, err = client.post("api/v2/torrents/resume", opts)
	}
	if err != nil {
		return
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// Delete torrents and optionally delete their files
func (client *Client) Delete(hashes []string, deleteFiles bool) (err error) {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	opts["deleteFiles"] = strconv.FormatBool(deleteFiles)
	resp, err := client.post("api/v2/torrents/delete", opts)
	if err != nil {
		return
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// Recheck torrents
func (client *Client) Recheck(hashes []string) (err error) {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/recheck", opts)
	if err != nil {
		return
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// Reannounce torrents
func (client *Client) Reannounce(hashes []string) (err error) {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/reannounce", opts)
	if err != nil {
		return
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// DownloadLinks adds torrents from magnet links or HTTP .torrent URLs (api/v2/torrents/add).
// Returns TorrentsAddResult when the server responds with JSON (API >= 2.14.0), or nil for older servers.
func (client *Client) DownloadLinks(links []string, opts DownloadOptions) (*TorrentsAddResult, error) {
	params := map[string]string{}
	if len(links) == 0 {
		return nil, wrapper.Errorf("At least one url must be present")
	}
	delimitedURLs := delimit(links, "%0A")
	// URLs are joined with newline encoding (%0A); do not apply a second full-string escape here.
	params["urls"] = delimitedURLs
	if opts.Savepath != nil {
		params["savepath"] = *opts.Savepath
	}
	if opts.Cookie != nil {
		params["cookie"] = *opts.Cookie
	}
	if opts.Category != nil {
		params["category"] = *opts.Category
	}
	if opts.SkipHashChecking != nil {
		params["skip_checking"] = strconv.FormatBool(*opts.SkipHashChecking)
	}
	if opts.Paused != nil {
		params["paused"] = strconv.FormatBool(*opts.Paused)
	}
	if opts.RootFolder != nil {
		params["root_folder"] = strconv.FormatBool(*opts.RootFolder)
	}
	if opts.Rename != nil {
		params["rename"] = *opts.Rename
	}
	if opts.UploadSpeedLimit != nil {
		params["upLimit"] = strconv.Itoa(*opts.UploadSpeedLimit)
	}
	if opts.DownloadSpeedLimit != nil {
		params["dlLimit"] = strconv.Itoa(*opts.DownloadSpeedLimit)
	}
	if opts.SequentialDownload != nil {
		params["sequentialDownload"] = strconv.FormatBool(*opts.SequentialDownload)
	}
	if opts.FirstLastPiecePriority != nil {
		params["firstLastPiecePrio"] = strconv.FormatBool(*opts.FirstLastPiecePriority)
	}

	resp, err := client.postMultipartData("api/v2/torrents/add", params)
	if err != nil {
		return nil, err
	}
	return parseTorrentsAddResponse(resp)
}

// DownloadFromFile adds a torrent from a local .torrent path (multipart upload).
// Returns TorrentsAddResult when the server responds with JSON (API >= 2.14.0), or nil for older servers.
func (client *Client) DownloadFromFile(torrents string, opts DownloadOptions) (*TorrentsAddResult, error) {
	params := map[string]string{}
	if torrents == "" {
		return nil, wrapper.Errorf("At least one file must be present")
	}
	if opts.Savepath != nil {
		params["savepath"] = *opts.Savepath
	}
	if opts.Cookie != nil {
		params["cookie"] = *opts.Cookie
	}
	if opts.Category != nil {
		params["category"] = *opts.Category
	}
	if opts.SkipHashChecking != nil {
		params["skip_checking"] = strconv.FormatBool(*opts.SkipHashChecking)
	}
	if opts.Paused != nil {
		params["paused"] = strconv.FormatBool(*opts.Paused)
	}
	if opts.RootFolder != nil {
		params["root_folder"] = strconv.FormatBool(*opts.RootFolder)
	}
	if opts.Rename != nil {
		params["rename"] = *opts.Rename
	}
	if opts.UploadSpeedLimit != nil {
		params["upLimit"] = strconv.Itoa(*opts.UploadSpeedLimit)
	}
	if opts.DownloadSpeedLimit != nil {
		params["dlLimit"] = strconv.Itoa(*opts.DownloadSpeedLimit)
	}
	if opts.AutomaticTorrentManagement != nil {
		params["autoTMM"] = strconv.FormatBool(*opts.AutomaticTorrentManagement)
	}
	if opts.SequentialDownload != nil {
		params["sequentialDownload"] = strconv.FormatBool(*opts.SequentialDownload)
	}
	if opts.FirstLastPiecePriority != nil {
		params["firstLastPiecePrio"] = strconv.FormatBool(*opts.FirstLastPiecePriority)
	}
	resp, err := client.postMultipartFile("api/v2/torrents/add", torrents, params)
	if err != nil {
		return nil, err
	}
	return parseTorrentsAddResponse(resp)
}

// parseTorrentsAddResponse handles the response from api/v2/torrents/add.
// API >= 2.14.0 returns a JSON body and may use 202 (pending) or 409 (all failed).
// Older servers return 200 with plain text "Ok." on success or 415 for invalid input.
func parseTorrentsAddResponse(resp *http.Response) (*TorrentsAddResult, error) {
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	switch resp.StatusCode {
	case 415:
		return nil, wrapper.Errorf("Torrent file is not valid")
	case 409:
		return nil, wrapper.Errorf("All torrents failed to be added")
	case 200, 202:
		var result TorrentsAddResult
		if json.Unmarshal(body, &result) == nil && (result.SuccessCount > 0 || result.PendingCount > 0 || result.FailureCount > 0) {
			return &result, nil
		}
		return nil, nil
	default:
		return nil, wrapper.Errorf("torrents/add: unexpected status %v: %s", resp.StatusCode, string(body))
	}
}

// AddTrackers appends trackers to a torrent.
func (client *Client) AddTrackers(hash string, trackers []string) error {
	params := make(map[string]string)
	params["hash"] = strings.ToLower(hash)
	delimitedTrackers := delimit(trackers, "%0A")
	encodedTrackers := url.QueryEscape(delimitedTrackers)
	params["urls"] = encodedTrackers

	resp, err := client.post("api/v2/torrents/addTrackers", params)
	if err != nil {
		return err
	} else if resp != nil && resp.StatusCode == 404 {
		return wrapper.Errorf("Torrent hash not found")
	}
	return nil
}

// EditTracker replaces one tracker URL with another.
func (client *Client) EditTracker(hash string, origURL string, newURL string) error {
	params := map[string]string{
		"hash":   strings.ToLower(hash),
		"url":    origURL,
		"newUrl": newURL,
	}
	resp, err := client.post("api/v2/torrents/editTracker", params)
	if err != nil {
		return err
	}
	switch sc := resp.StatusCode; sc {
	case 400:
		return wrapper.Errorf("newUrl is not a valid url")
	case 404:
		return wrapper.Errorf("Torrent hash was not found")
	case 409:
		return wrapper.Errorf("newUrl already exists for this torrent or origUrl was not found")
	default:
		return nil
	}
}

// RemoveTrackers removes tracker URLs from a torrent.
func (client *Client) RemoveTrackers(hash string, trackers []string) error {
	params := map[string]string{
		"hash": strings.ToLower(hash),
		"urls": delimit(trackers, "|"),
	}
	resp, err := client.post("api/v2/torrents/removeTrackers", params)
	if err != nil {
		return err
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	case 404:
		return wrapper.Errorf("Torrent hash was not found")
	case 409:
		return wrapper.Errorf("All URLs were not found")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// IncreasePriority moves torrents up in the queue (requires queueing enabled).
func (client *Client) IncreasePriority(hashes []string) error {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/increasePrio", opts)
	if err != nil {
		return err
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	case 409:
		return wrapper.Errorf("Torrent queueing is not enabled")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// DecreasePriority moves torrents down in the queue (requires queueing enabled).
func (client *Client) DecreasePriority(hashes []string) error {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/decreasePrio", opts)
	if err != nil {
		return err
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	case 409:
		return wrapper.Errorf("Torrent queueing is not enabled")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// MaxPriority moves torrents to the top of the queue (requires queueing enabled).
func (client *Client) MaxPriority(hashes []string) error {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/topPrio", opts)
	if err != nil {
		return err
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	case 409:
		return wrapper.Errorf("Torrent queueing is not enabled")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// MinPriority moves torrents to the bottom of the queue (requires queueing enabled).
func (client *Client) MinPriority(hashes []string) error {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/bottomPrio", opts)
	if err != nil {
		return err
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	case 409:
		return wrapper.Errorf("Torrent queueing is not enabled")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// FilePriority sets priority for file IDs within a torrent.
func (client *Client) FilePriority(hash string, ids []int, priority int) error {
	formattedIds := []string{}
	for _, id := range ids {
		formattedIds = append(formattedIds, strconv.Itoa(id))
	}

	opts := map[string]string{
		"hash":     hash,
		"id":       delimit(formattedIds, "|"),
		"priority": strconv.Itoa(priority),
	}
	resp, err := client.post("api/v2/torrents/filePrio", opts)
	if err != nil {
		return err
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	case 400:
		return wrapper.Errorf("Priority is invalid or at least one id is not an integer")
	case 409:
		return wrapper.Errorf("Torrent metadata hasn't downloaded yet or at least one file id was not found")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// GetTorrentDownloadLimit returns per-torrent download limits.
func (client *Client) GetTorrentDownloadLimit(hashes []string) (limits map[string]int, err error) {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/downloadLimit", opts)
	if err != nil {
		return limits, err
	}
	json.NewDecoder(resp.Body).Decode(&limits)
	return limits, nil
}

// SetTorrentDownloadLimit sets per-torrent download limits.
func (client *Client) SetTorrentDownloadLimit(hashes []string, limit int) (err error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"limit":  strconv.Itoa(limit),
	}
	resp, err := client.post("api/v2/torrents/setDownloadLimit", opts)
	if err != nil {
		return
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// ShareLimitAction controls what happens when a torrent exceeds its share limit (API >= 2.12.0).
type ShareLimitAction string

const (
	ShareLimitActionDefault           ShareLimitAction = "Default"
	ShareLimitActionStop              ShareLimitAction = "Stop"
	ShareLimitActionRemove            ShareLimitAction = "Remove"
	ShareLimitActionRemoveWithContent ShareLimitAction = "RemoveWithContent"
	ShareLimitActionEnableSuperSeeding ShareLimitAction = "EnableSuperSeeding"
)

// SetTorrentShareLimit sets ratio and seeding time limits for torrents.
// shareLimitAction is required by API >= 2.12.0; pass ShareLimitActionDefault to keep the existing behaviour.
func (client *Client) SetTorrentShareLimit(hashes []string, ratioLimit int, seedingTimeLimit int, shareLimitAction ShareLimitAction) (err error) {
	if shareLimitAction == "" {
		shareLimitAction = ShareLimitActionDefault
	}
	opts := map[string]string{
		"hashes":           delimit(hashes, "|"),
		"ratioLimit":       strconv.Itoa(ratioLimit),
		"seedingTimeLimit": strconv.Itoa(seedingTimeLimit),
		"shareLimitAction": string(shareLimitAction),
	}
	resp, err := client.post("api/v2/torrents/setShareLimits", opts)
	if err != nil {
		return
	}
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// GetTorrentUploadLimit returns per-torrent upload limits.
func (client *Client) GetTorrentUploadLimit(hashes []string) (limits map[string]int, err error) {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/uploadLimit", opts)
	if err != nil {
		return limits, err
	}
	json.NewDecoder(resp.Body).Decode(&limits)
	return limits, nil
}

// SetTorrentUploadLimit sets per-torrent upload limits.
func (client *Client) SetTorrentUploadLimit(hashes []string, limit int) (err error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"limit":  strconv.Itoa(limit),
	}
	resp, err := client.post("api/v2/torrents/setUploadLimit", opts)
	if err != nil {
		return
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// SetTorrentLocation sets the save path for torrents.
func (client *Client) SetTorrentLocation(hashes []string, location string) (err error) {
	opts := map[string]string{
		"hashes":   delimit(hashes, "|"),
		"location": location,
	}
	resp, err := client.post("api/v2/torrents/setLocation", opts)
	if err != nil {
		return
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	case 400:
		return wrapper.Errorf("Save path is empty")
	case 403:
		return wrapper.Errorf("User does not have write access to directory")
	case 409:
		return wrapper.Errorf("Unable to create save path directory")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// SetTorrentName renames a torrent in the session.
func (client *Client) SetTorrentName(hash string, name string) (err error) {
	opts := map[string]string{
		"hash": hash,
		"name": name,
	}
	resp, err := client.post("api/v2/torrents/rename", opts)
	if err != nil {
		return
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	case 404:
		return wrapper.Errorf("Torrent hash is invalid")
	case 409:
		return wrapper.Errorf("Torrent name is empty")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// SetTorrentCategory assigns a category to torrents.
func (client *Client) SetTorrentCategory(hashes []string, category string) (err error) {
	opts := map[string]string{
		"hashes":   delimit(hashes, "|"),
		"category": category,
	}
	resp, err := client.post("api/v2/torrents/setCategory", opts)
	if err != nil {
		return
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	case 409:
		return wrapper.Errorf("Category name does not exist")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// GetCategories returns all categories (api/v2/torrents/categories).
func (client *Client) GetCategories() (categories Categories, err error) {
	resp, err := client.post("api/v2/torrents/categories", nil)
	if err != nil {
		return categories, err
	}
	json.NewDecoder(resp.Body).Decode(&categories)
	return categories, nil
}

// CreateCategory creates a category with an optional save path.
func (client *Client) CreateCategory(category string, savePath string) (err error) {
	opts := map[string]string{
		"category": category,
		"savePath": savePath,
	}
	resp, err := client.post("api/v2/torrents/createCategory", opts)
	if err != nil {
		return
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	case 400:
		return wrapper.Errorf("Category name is empty")
	case 409:
		return wrapper.Errorf("Category name is invalid")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// UpdateCategory changes a category's save path.
func (client *Client) UpdateCategory(category string, savePath string) (err error) {
	opts := map[string]string{
		"category": category,
		"savePath": savePath,
	}
	resp, err := client.post("api/v2/torrents/editCategory", opts)
	if err != nil {
		return
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	case 400:
		return wrapper.Errorf("Category name is empty")
	case 404:
		return wrapper.Errorf("Category not found")
	case 409:
		return wrapper.Errorf("Category editing failed")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// DeleteCategories removes categories by name.
func (client *Client) DeleteCategories(categories []string) (err error) {
	opts := map[string]string{"categories": delimit(categories, "\n")}
	resp, err := client.post("api/v2/torrents/removeCategories", opts)
	if err != nil {
		return
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// AddTorrentTags adds tags to torrents.
func (client *Client) AddTorrentTags(hashes []string, tags []string) (err error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"tags":   delimit(tags, ","),
	}
	resp, err := client.post("api/v2/torrents/addTags", opts)
	if err != nil {
		return err
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// RemoveTorrentTags from a list of torrents (empty list removes all tags)
func (client *Client) RemoveTorrentTags(hashes []string, tags []string) (err error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"tags":   delimit(tags, ","),
	}
	resp, err := client.post("api/v2/torrents/removeTags", opts)
	if err != nil {
		return
	}

	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// GetTorrentTags returns all tags defined in the session (api/v2/torrents/tags).
func (client *Client) GetTorrentTags() (tags []string, err error) {
	resp, err := client.get("api/v2/torrents/tags", nil)
	if err != nil {
		return nil, err
	}
	json.NewDecoder(resp.Body).Decode(&tags)
	return tags, nil
}

// CreateTags defines new tags in the session.
func (client *Client) CreateTags(tags []string) (err error) {
	opts := map[string]string{"tags": delimit(tags, ",")}
	resp, err := client.post("api/v2/torrents/createTags", opts)
	if err != nil {
		return
	}
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// DeleteTags removes tags from the session.
func (client *Client) DeleteTags(tags []string) (err error) {
	opts := map[string]string{"tags": delimit(tags, ",")}
	resp, err := client.post("api/v2/torrents/deleteTags", opts)
	if err != nil {
		return
	}
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// SetAutoManagement toggles automatic torrent management for torrents.
func (client *Client) SetAutoManagement(hashes []string, enable bool) (err error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"enable": strconv.FormatBool(enable),
	}
	resp, err := client.post("api/v2/torrents/setAutoManagement", opts)
	if err != nil {
		return
	}
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// ToggleSequentialDownload toggles sequential download for torrents.
func (client *Client) ToggleSequentialDownload(hashes []string) (err error) {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/toggleSequentialDownload", opts)
	if err != nil {
		return
	}
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// ToggleFirstLastPiecePriority toggles first/last piece priority for torrents.
func (client *Client) ToggleFirstLastPiecePriority(hashes []string) (err error) {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/toggleFirstLastPiecePrio", opts)
	if err != nil {
		return
	}
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// SetForceStart sets force-start mode for torrents.
func (client *Client) SetForceStart(hashes []string, value bool) (err error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"value":  strconv.FormatBool(value),
	}
	resp, err := client.post("api/v2/torrents/setForceStart", opts)
	if err != nil {
		return
	}
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// SetSuperSeeding sets super seeding mode for torrents.
func (client *Client) SetSuperSeeding(hashes []string, value bool) (err error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"value":  strconv.FormatBool(value),
	}
	resp, err := client.post("api/v2/torrents/setSuperSeeding", opts)
	if err != nil {
		return
	}
	switch sc := resp.StatusCode; sc {
	case 200, 204:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}
