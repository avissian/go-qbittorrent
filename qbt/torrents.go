package qbt

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	wrapper "github.com/pkg/errors"
)

// Torrents returns a list of all torrents in qbittorrent matching your filter
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

// Torrent returns a specific torrent matching the hash
func (client *Client) Torrent(hash string) (torrent Torrent, err error) {
	var opts = map[string]string{"hash": strings.ToLower(hash)}
	resp, err := client.get("api/v2/torrents/properties", opts)
	if err != nil {
		return torrent, err
	}
	json.NewDecoder(resp.Body).Decode(&torrent)
	return torrent, nil
}

// TorrentTrackers returns all trackers for a specific torrent matching the hash
func (client *Client) TorrentTrackers(hash string) (trackers []Tracker, err error) {
	var opts = map[string]string{"hash": strings.ToLower(hash)}
	resp, err := client.get("api/v2/torrents/trackers", opts)
	if err != nil {
		return trackers, err
	}
	json.NewDecoder(resp.Body).Decode(&trackers)
	return trackers, nil
}

// TorrentWebSeeds returns seeders for a specific torrent matching the hash
func (client *Client) TorrentWebSeeds(hash string) (webSeeds []WebSeed, err error) {
	var opts = map[string]string{"hash": strings.ToLower(hash)}
	resp, err := client.get("api/v2/torrents/webseeds", opts)
	if err != nil {
		return webSeeds, err
	}
	json.NewDecoder(resp.Body).Decode(&webSeeds)
	return webSeeds, nil
}

// TorrentFiles from given hash
func (client *Client) TorrentFiles(hash string) (files []TorrentFile, err error) {
	var opts = map[string]string{"hash": strings.ToLower(hash)}
	resp, err := client.get("api/v2/torrents/files", opts)
	if err != nil {
		return files, err
	}
	json.NewDecoder(resp.Body).Decode(&files)
	return files, nil
}

// TorrentPieceStates for all pieces of torrent
func (client *Client) TorrentPieceStates(hash string) (states []int, err error) {
	var opts = map[string]string{"hash": strings.ToLower(hash)}
	resp, err := client.get("api/v2/torrents/pieceStates", opts)
	if err != nil {
		return states, err
	}
	json.NewDecoder(resp.Body).Decode(&states)
	return states, nil
}

// TorrentPieceHashes for all pieces of torrent
func (client *Client) TorrentPieceHashes(hash string) (hashes []string, err error) {
	var opts = map[string]string{"hash": strings.ToLower(hash)}
	resp, err := client.get("api/v2/torrents/pieceHashes", opts)
	if err != nil {
		return hashes, err
	}
	json.NewDecoder(resp.Body).Decode(&hashes)
	return hashes, nil
}

// Pause torrents
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

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// Resume torrents
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

	switch sc := (*resp).StatusCode; sc {
	case 200:
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

	switch sc := (*resp).StatusCode; sc {
	case 200:
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

	switch sc := (*resp).StatusCode; sc {
	case 200:
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

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// DownloadFromLink starts downloading a torrent from a link
func (client *Client) DownloadLinks(links []string, opts DownloadOptions) error {
	params := map[string]string{}
	if len(links) == 0 {
		return wrapper.Errorf("At least one url must be present")
	} else {
		delimitedURLs := delimit(links, "%0A")
		// TODO: Why is encoding causing problems now?
		// encodedURLS := url.QueryEscape(delimitedURLs)
		params["urls"] = delimitedURLs
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
	if opts.SequentialDownload != nil {
		params["sequentialDownload"] = strconv.FormatBool(*opts.SequentialDownload)
	}
	if opts.FirstLastPiecePriority != nil {
		params["firstLastPiecePrio"] = strconv.FormatBool(*opts.FirstLastPiecePriority)
	}

	resp, err := client.postMultipartData("api/v2/torrents/add", params)
	if err != nil {
		return err
	} else if resp.StatusCode == 415 {
		return wrapper.Errorf("Torrent file is not valid")
	}

	return nil
}

// DownloadFromFile starts downloading a torrent from a file
func (client *Client) DownloadFromFile(torrents string, opts DownloadOptions) error {
	params := map[string]string{}
	if torrents == "" {
		return wrapper.Errorf("At least one file must be present")
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
		return err
	} else if resp.StatusCode == 415 {
		return wrapper.Errorf("Torrent file is not valid")
	}

	return nil
}

// AddTrackers to a torrent
func (client *Client) AddTrackers(hash string, trackers []string) error {
	params := make(map[string]string)
	params["hash"] = strings.ToLower(hash)
	delimitedTrackers := delimit(trackers, "%0A")
	encodedTrackers := url.QueryEscape(delimitedTrackers)
	params["urls"] = encodedTrackers

	resp, err := client.post("api/v2/torrents/addTrackers", params)
	if err != nil {
		return err
	} else if resp != nil && (*resp).StatusCode == 404 {
		return wrapper.Errorf("Torrent hash not found")
	}
	return nil
}

// EditTracker on a torrent
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
	switch sc := (*resp).StatusCode; sc {
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

// RemoveTrackers from a torrent
func (client *Client) RemoveTrackers(hash string, trackers []string) error {
	params := map[string]string{
		"hash": strings.ToLower(hash),
		"urls": delimit(trackers, "|"),
	}
	resp, err := client.post("api/v2/torrents/removeTrackers", params)
	if err != nil {
		return err
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	case 404:
		return wrapper.Errorf("Torrent hash was not found")
	case 409:
		return wrapper.Errorf("All URLs were not found")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// IncreasePriority of torrents
func (client *Client) IncreasePriority(hashes []string) error {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/increasePrio", opts)
	if err != nil {
		return err
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	case 409:
		return wrapper.Errorf("Torrent queueing is not enabled")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// DecreasePriority of torrents
func (client *Client) DecreasePriority(hashes []string) error {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/decreasePrio", opts)
	if err != nil {
		return err
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	case 409:
		return wrapper.Errorf("Torrent queueing is not enabled")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// MaxPriority maximizes the priority of torrents
func (client *Client) MaxPriority(hashes []string) error {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/topPrio", opts)
	if err != nil {
		return err
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	case 409:
		return wrapper.Errorf("Torrent queueing is not enabled")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// MinPriority maximizes the priority of torrents
func (client *Client) MinPriority(hashes []string) error {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/bottomPrio", opts)
	if err != nil {
		return err
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	case 409:
		return wrapper.Errorf("Torrent queueing is not enabled")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// FilePriority for a torrent
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

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	case 400:
		return wrapper.Errorf("Priority is invalid or at least one id is not an integer")
	case 409:
		return wrapper.Errorf("Torrent metadata hasn't downloaded yet or at least one file id was not found")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// GetTorrentDownloadLimit for a list of torrents
func (client *Client) GetTorrentDownloadLimit(hashes []string) (limits map[string]int, err error) {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/downloadLimit", opts)
	if err != nil {
		return limits, err
	}
	json.NewDecoder(resp.Body).Decode(&limits)
	return limits, nil
}

// SetTorrentDownloadLimit for a list of torrents
func (client *Client) SetTorrentDownloadLimit(hashes []string, limit int) (err error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"limit":  strconv.Itoa(limit),
	}
	resp, err := client.post("api/v2/torrents/setDownloadLimit", opts)
	if err != nil {
		return
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// SetTorrentShareLimit for a list of torrents
func (client *Client) SetTorrentShareLimit(hashes []string, ratioLimit int, seedingTimeLimit int) (err error) {
	opts := map[string]string{
		"hashes":           delimit(hashes, "|"),
		"ratioLimit":       strconv.Itoa(ratioLimit),
		"seedingTimeLimit": strconv.Itoa(seedingTimeLimit),
	}
	resp, err := client.post("api/v2/torrents/setShareLimits", opts)
	if err != nil {
		return
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// GetTorrentUploadLimit for a list of torrents
func (client *Client) GetTorrentUploadLimit(hashes []string) (limits map[string]int, err error) {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/uploadLimit", opts)
	if err != nil {
		return limits, err
	}
	json.NewDecoder(resp.Body).Decode(&limits)
	return limits, nil
}

// SetTorrentUploadLimit for a list of torrents
func (client *Client) SetTorrentUploadLimit(hashes []string, limit int) (err error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"limit":  strconv.Itoa(limit),
	}
	resp, err := client.post("api/v2/torrents/setUploadLimit", opts)
	if err != nil {
		return
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// SetTorrentLocation for a list of torrents
func (client *Client) SetTorrentLocation(hashes []string, location string) (err error) {
	opts := map[string]string{
		"hashes":   delimit(hashes, "|"),
		"location": location,
	}
	resp, err := client.post("api/v2/torrents/setLocation", opts)
	if err != nil {
		return
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
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

// SetTorrentName for a torrent
func (client *Client) SetTorrentName(hash string, name string) (err error) {
	opts := map[string]string{
		"hash": hash,
		"name": name,
	}
	resp, err := client.post("api/v2/torrents/rename", opts)
	if err != nil {
		return
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	case 404:
		return wrapper.Errorf("Torrent hash is invalid")
	case 409:
		return wrapper.Errorf("Torrent name is empty")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// SetTorrentCategory for a list of torrents
func (client *Client) SetTorrentCategory(hashes []string, category string) (err error) {
	opts := map[string]string{
		"hashes":   delimit(hashes, "|"),
		"category": category,
	}
	resp, err := client.post("api/v2/torrents/setCategory", opts)
	if err != nil {
		return
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	case 409:
		return wrapper.Errorf("Category name does not exist")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// GetCategories used by client
func (client *Client) GetCategories() (categories Categories, err error) {
	resp, err := client.post("api/v2/torrents/categories", nil)
	if err != nil {
		return categories, err
	}
	json.NewDecoder(resp.Body).Decode(&categories)
	return categories, nil
}

// CreateCategory for use by client
func (client *Client) CreateCategory(category string, savePath string) (err error) {
	opts := map[string]string{
		"category": category,
		"savePath": savePath,
	}
	resp, err := client.post("api/v2/torrents/createCategory", opts)
	if err != nil {
		return
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	case 400:
		return wrapper.Errorf("Category name is empty")
	case 409:
		return wrapper.Errorf("Category name is invalid")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// UpdateCategory used by client
func (client *Client) UpdateCategory(category string, savePath string) (err error) {
	opts := map[string]string{
		"category": category,
		"savePath": savePath,
	}
	resp, err := client.post("api/v2/torrents/editCategory", opts)
	if err != nil {
		return
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	case 400:
		return wrapper.Errorf("Category name is empty")
	case 409:
		return wrapper.Errorf("Category editing failed")
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// DeleteCategories used by client
func (client *Client) DeleteCategories(categories []string) (err error) {
	opts := map[string]string{"categories": delimit(categories, "\n")}
	resp, err := client.post("api/v2/torrents/removeCategories", opts)
	if err != nil {
		return
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// AddTorrentTags to a list of torrents
func (client *Client) AddTorrentTags(hashes []string, tags []string) (err error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"tags":   delimit(tags, ","),
	}
	resp, err := client.post("api/v2/torrents/addTags", opts)
	if err != nil {
		return err
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
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

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// GetTorrentTags from a list of torrents (empty list removes all tags)
func (client *Client) GetTorrentTags() (tags []string, err error) {
	resp, err := client.get("api/v2/torrents/tags", nil)
	if err != nil {
		return nil, err
	}
	json.NewDecoder(resp.Body).Decode(&tags)
	return tags, nil
}

// CreateTags for use by client
func (client *Client) CreateTags(tags []string) (err error) {
	opts := map[string]string{"tags": delimit(tags, ",")}
	resp, err := client.post("api/v2/torrents/createTags", opts)
	if err != nil {
		return
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// DeleteTags used by client
func (client *Client) DeleteTags(tags []string) (err error) {
	opts := map[string]string{"tags": delimit(tags, ",")}
	resp, err := client.post("api/v2/torrents/deleteTags", opts)
	if err != nil {
		return
	}

	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// SetAutoManagement for a list of torrents
func (client *Client) SetAutoManagement(hashes []string, enable bool) (err error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"enable": strconv.FormatBool(enable),
	}
	resp, err := client.post("api/v2/torrents/setAutoManagement", opts)
	if err != nil {
		return
	}
	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// ToggleSequentialDownload for a list of torrents
func (client *Client) ToggleSequentialDownload(hashes []string) (err error) {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/toggleSequentialDownload", opts)
	if err != nil {
		return
	}
	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// ToggleFirstLastPiecePriority for a list of torrents
func (client *Client) ToggleFirstLastPiecePriority(hashes []string) (err error) {
	opts := map[string]string{"hashes": delimit(hashes, "|")}
	resp, err := client.post("api/v2/torrents/toggleFirstLastPiecePrio", opts)
	if err != nil {
		return
	}
	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// SetForceStart for a list of torrents
func (client *Client) SetForceStart(hashes []string, value bool) (err error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"value":  strconv.FormatBool(value),
	}
	resp, err := client.post("api/v2/torrents/setForceStart", opts)
	if err != nil {
		return
	}
	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}

// SetSuperSeeding for a list of torrents
func (client *Client) SetSuperSeeding(hashes []string, value bool) (err error) {
	opts := map[string]string{
		"hashes": delimit(hashes, "|"),
		"value":  strconv.FormatBool(value),
	}
	resp, err := client.post("api/v2/torrents/setSuperSeeding", opts)
	if err != nil {
		return
	}
	switch sc := (*resp).StatusCode; sc {
	case 200:
		return nil
	default:
		return wrapper.Errorf("An unknown error occurred causing a status code of: %v", sc)
	}
}
