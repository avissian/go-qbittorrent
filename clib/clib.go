// Package main exposes the qBittorrent Web API client as a C-compatible shared library.
//
// Build:
//
//	go build -buildmode=c-shared -o libqbt.so  ./clib/   # Linux
//	go build -buildmode=c-shared -o libqbt.dylib ./clib/ # macOS
//	go build -buildmode=c-shared -o libqbt.dll  ./clib/  # Windows
//
// The compiler also generates a libqbt.h header with all exported signatures.
//
// # Handle lifecycle
//
//	uintptr_t h = QbtNewClient("http://127.0.0.1:8080/");
//	QbtLogin(h, "admin", "adminadmin");
//	/* ... use the client ... */
//	QbtFreeClient(h);
//
// # String ownership
//
// Every function that returns a `char*` allocates a new C string on the heap.
// The caller MUST release it with QbtFreeString(). Passing NULL or an empty
// string for optional parameters is always safe.
//
// # Error handling
//
// Status functions return 0 on success or -1 on error.
// Call QbtLastError(h) after any failure to obtain the message.
package main

/*
#include <stdint.h>  // uintptr_t, uint64_t
#include <stdlib.h>  // free
*/
import "C"

import (
	"encoding/json"
	"runtime/cgo"
	"strings"
	"sync"
	"unsafe"

	"github.com/avissian/go-qbittorrent/qbt"
)

// clientCtx holds a Client together with the last error so callers can
// query it with QbtLastError without worrying about thread safety.
type clientCtx struct {
	client  *qbt.Client
	mu      sync.Mutex
	lastErr string
}

func getCtx(h C.uintptr_t) *clientCtx {
	return cgo.Handle(h).Value().(*clientCtx)
}

// setErr stores err (if non-nil) and returns -1; clears lastErr and returns 0 on nil.
func (ctx *clientCtx) setErr(err error) C.int {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if err != nil {
		ctx.lastErr = err.Error()
		return -1
	}
	ctx.lastErr = ""
	return 0
}

// goStr converts a *C.char to a Go string, returning "" for nil.
func goStr(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}

// splitPipe splits a pipe-separated C string into a Go slice, returning nil for
// empty/nil input.
func splitPipe(s *C.char) []string {
	gs := goStr(s)
	if gs == "" {
		return nil
	}
	return strings.Split(gs, "|")
}

// marshalJSON encodes v as JSON, stores any encoding error, and returns a
// malloc'd C string (caller must free with QbtFreeString).
func marshalJSON(v any, ctx *clientCtx) *C.char {
	b, err := json.Marshal(v)
	if err != nil {
		ctx.setErr(err)
		return C.CString("")
	}
	ctx.setErr(nil)
	return C.CString(string(b))
}

func main() {}

// ---------------------------------------------------------------------------
// Client lifecycle
// ---------------------------------------------------------------------------

// QbtNewClient creates a new client for the given Web UI base URL and returns
// an opaque handle. The handle must eventually be released with QbtFreeClient.
//
//export QbtNewClient
func QbtNewClient(rawURL *C.char) C.uintptr_t {
	ctx := &clientCtx{client: qbt.NewClient(goStr(rawURL))}
	return C.uintptr_t(cgo.NewHandle(ctx))
}

// QbtFreeClient releases all resources associated with the handle.
// The handle must not be used after this call.
//
//export QbtFreeClient
func QbtFreeClient(h C.uintptr_t) {
	cgo.Handle(h).Delete()
}

// QbtLastError returns a malloc'd string with the last error message for the
// given handle, or an empty string if the last operation succeeded.
// Caller must free with QbtFreeString.
//
//export QbtLastError
func QbtLastError(h C.uintptr_t) *C.char {
	ctx := getCtx(h)
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return C.CString(ctx.lastErr)
}

// QbtFreeString releases a C string previously returned by this library.
//
//export QbtFreeString
func QbtFreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

// QbtLogin authenticates against the Web UI. Returns 0 on success, -1 on error.
//
//export QbtLogin
func QbtLogin(h C.uintptr_t, username, password *C.char) C.int {
	ctx := getCtx(h)
	err := ctx.client.Login(qbt.LoginOptions{
		Username: goStr(username),
		Password: goStr(password),
	})
	return ctx.setErr(err)
}

// QbtLogout ends the Web UI session. Returns 0 on success, -1 on error.
//
//export QbtLogout
func QbtLogout(h C.uintptr_t) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.Logout())
}

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------

// QbtAppVersion returns a malloc'd string with the qBittorrent application
// version, e.g. "5.2.0". Caller must free with QbtFreeString.
//
//export QbtAppVersion
func QbtAppVersion(h C.uintptr_t) *C.char {
	ctx := getCtx(h)
	v, err := ctx.client.ApplicationVersion()
	ctx.setErr(err)
	return C.CString(v)
}

// QbtWebAPIVersion returns a malloc'd string with the Web API version,
// e.g. "2.16.0". Caller must free with QbtFreeString.
//
//export QbtWebAPIVersion
func QbtWebAPIVersion(h C.uintptr_t) *C.char {
	ctx := getCtx(h)
	v, err := ctx.client.WebAPIVersion()
	ctx.setErr(err)
	return C.CString(v)
}

// QbtPreferencesJSON returns application preferences as a malloc'd JSON string.
// Returns "" on error. Caller must free with QbtFreeString.
//
//export QbtPreferencesJSON
func QbtPreferencesJSON(h C.uintptr_t) *C.char {
	ctx := getCtx(h)
	prefs, err := ctx.client.Preferences()
	if err != nil {
		ctx.setErr(err)
		return C.CString("")
	}
	return marshalJSON(prefs, ctx)
}

// QbtDefaultSavePath returns the default save directory as a malloc'd string.
// Caller must free with QbtFreeString.
//
//export QbtDefaultSavePath
func QbtDefaultSavePath(h C.uintptr_t) *C.char {
	ctx := getCtx(h)
	p, err := ctx.client.DefaultSavePath()
	ctx.setErr(err)
	return C.CString(p)
}

// ---------------------------------------------------------------------------
// Transfer
// ---------------------------------------------------------------------------

// QbtTransferInfoJSON returns global transfer statistics as a malloc'd JSON
// string. Returns "" on error. Caller must free with QbtFreeString.
//
//export QbtTransferInfoJSON
func QbtTransferInfoJSON(h C.uintptr_t) *C.char {
	ctx := getCtx(h)
	info, err := ctx.client.Info(qbt.InfoOptions{})
	if err != nil {
		ctx.setErr(err)
		return C.CString("")
	}
	return marshalJSON(info, ctx)
}

// QbtSetDlLimit sets the global download speed limit in bytes/s (0 = unlimited).
// Returns 0 on success, -1 on error.
//
//export QbtSetDlLimit
func QbtSetDlLimit(h C.uintptr_t, limit C.int) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.SetDlLimit(int(limit)))
}

// QbtSetUlLimit sets the global upload speed limit in bytes/s (0 = unlimited).
// Returns 0 on success, -1 on error.
//
//export QbtSetUlLimit
func QbtSetUlLimit(h C.uintptr_t, limit C.int) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.SetUlLimit(int(limit)))
}

// ---------------------------------------------------------------------------
// Torrents — listing & properties
// ---------------------------------------------------------------------------

// QbtTorrentsJSON returns the torrent list as a malloc'd JSON array string.
//
// filter, category, sort may be NULL or "" to omit the parameter.
// Pass reverse=1 to sort in reverse order.
// Pass limit=0 / offset=0 to use server defaults.
//
// Returns "" on error. Caller must free with QbtFreeString.
//
//export QbtTorrentsJSON
func QbtTorrentsJSON(h C.uintptr_t, filter, category, sort *C.char, reverse, limit, offset C.int) *C.char {
	ctx := getCtx(h)
	opts := qbt.TorrentsOptions{}
	if f := goStr(filter); f != "" {
		opts.Filter = &f
	}
	if c := goStr(category); c != "" {
		opts.Category = &c
	}
	if s := goStr(sort); s != "" {
		opts.Sort = &s
	}
	if reverse != 0 {
		b := true
		opts.Reverse = &b
	}
	if limit > 0 {
		n := int(limit)
		opts.Limit = &n
	}
	if offset != 0 {
		n := int(offset)
		opts.Offset = &n
	}
	torrents, err := ctx.client.Torrents(opts)
	if err != nil {
		ctx.setErr(err)
		return C.CString("")
	}
	return marshalJSON(torrents, ctx)
}

// QbtTorrentJSON returns properties for a single torrent as a malloc'd JSON string.
// Returns "" on error. Caller must free with QbtFreeString.
//
//export QbtTorrentJSON
func QbtTorrentJSON(h C.uintptr_t, hash *C.char) *C.char {
	ctx := getCtx(h)
	t, err := ctx.client.Torrent(goStr(hash))
	if err != nil {
		ctx.setErr(err)
		return C.CString("")
	}
	return marshalJSON(t, ctx)
}

// QbtTorrentTrackersJSON returns the tracker list for a torrent as a malloc'd
// JSON array string. Returns "" on error. Caller must free with QbtFreeString.
//
//export QbtTorrentTrackersJSON
func QbtTorrentTrackersJSON(h C.uintptr_t, hash *C.char) *C.char {
	ctx := getCtx(h)
	trackers, err := ctx.client.TorrentTrackers(goStr(hash))
	if err != nil {
		ctx.setErr(err)
		return C.CString("")
	}
	return marshalJSON(trackers, ctx)
}

// ---------------------------------------------------------------------------
// Torrents — state control
// ---------------------------------------------------------------------------

// QbtPause pauses the torrents identified by pipe-separated hashes (e.g.
// "abc123|def456"). Pass "all" to pause every torrent.
// Returns 0 on success, -1 on error.
//
//export QbtPause
func QbtPause(h C.uintptr_t, hashes *C.char) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.Pause(splitPipe(hashes)))
}

// QbtResume resumes the torrents identified by pipe-separated hashes.
// Pass "all" to resume every torrent. Returns 0 on success, -1 on error.
//
//export QbtResume
func QbtResume(h C.uintptr_t, hashes *C.char) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.Resume(splitPipe(hashes)))
}

// QbtDelete deletes the torrents identified by pipe-separated hashes.
// Pass deleteFiles=1 to also remove downloaded content from disk.
// Returns 0 on success, -1 on error.
//
//export QbtDelete
func QbtDelete(h C.uintptr_t, hashes *C.char, deleteFiles C.int) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.Delete(splitPipe(hashes), deleteFiles != 0))
}

// QbtRecheck forces a data integrity check for the given pipe-separated hashes.
// Returns 0 on success, -1 on error.
//
//export QbtRecheck
func QbtRecheck(h C.uintptr_t, hashes *C.char) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.Recheck(splitPipe(hashes)))
}

// QbtReannounce re-announces the given pipe-separated hashes to trackers.
// Returns 0 on success, -1 on error.
//
//export QbtReannounce
func QbtReannounce(h C.uintptr_t, hashes *C.char) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.Reannounce(splitPipe(hashes)))
}

// ---------------------------------------------------------------------------
// Torrents — adding
// ---------------------------------------------------------------------------

// QbtDownloadLinks adds torrents from newline-separated magnet/HTTP URLs.
//
// savePath and category are optional (pass NULL or "").
// Returns a malloc'd JSON string with the add result (API >= 2.14.0) or "{}"
// for older servers. Returns "" on error. Caller must free with QbtFreeString.
//
//export QbtDownloadLinks
func QbtDownloadLinks(h C.uintptr_t, urls, savePath, category *C.char) *C.char {
	ctx := getCtx(h)
	rawURLs := goStr(urls)
	if rawURLs == "" {
		ctx.setErr(nil)
		return C.CString("{}")
	}
	links := strings.Split(rawURLs, "\n")
	opts := qbt.DownloadOptions{}
	if sp := goStr(savePath); sp != "" {
		opts.Savepath = &sp
	}
	if cat := goStr(category); cat != "" {
		opts.Category = &cat
	}
	result, err := ctx.client.DownloadLinks(links, opts)
	if err != nil {
		ctx.setErr(err)
		return C.CString("")
	}
	if result == nil {
		ctx.setErr(nil)
		return C.CString("{}")
	}
	return marshalJSON(result, ctx)
}

// QbtDownloadFromFile adds a torrent from a local .torrent file path.
//
// savePath and category are optional (pass NULL or "").
// Returns a malloc'd JSON string with the add result (API >= 2.14.0) or "{}"
// for older servers. Returns "" on error. Caller must free with QbtFreeString.
//
//export QbtDownloadFromFile
func QbtDownloadFromFile(h C.uintptr_t, filePath, savePath, category *C.char) *C.char {
	ctx := getCtx(h)
	opts := qbt.DownloadOptions{}
	if sp := goStr(savePath); sp != "" {
		opts.Savepath = &sp
	}
	if cat := goStr(category); cat != "" {
		opts.Category = &cat
	}
	result, err := ctx.client.DownloadFromFile(goStr(filePath), opts)
	if err != nil {
		ctx.setErr(err)
		return C.CString("")
	}
	if result == nil {
		ctx.setErr(nil)
		return C.CString("{}")
	}
	return marshalJSON(result, ctx)
}

// ---------------------------------------------------------------------------
// Torrents — limits & properties
// ---------------------------------------------------------------------------

// QbtSetTorrentDownloadLimit sets per-torrent download limit in bytes/s.
// hashes is pipe-separated. Returns 0 on success, -1 on error.
//
//export QbtSetTorrentDownloadLimit
func QbtSetTorrentDownloadLimit(h C.uintptr_t, hashes *C.char, limit C.int) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.SetTorrentDownloadLimit(splitPipe(hashes), int(limit)))
}

// QbtSetTorrentUploadLimit sets per-torrent upload limit in bytes/s.
// hashes is pipe-separated. Returns 0 on success, -1 on error.
//
//export QbtSetTorrentUploadLimit
func QbtSetTorrentUploadLimit(h C.uintptr_t, hashes *C.char, limit C.int) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.SetTorrentUploadLimit(splitPipe(hashes), int(limit)))
}

// QbtSetTorrentCategory assigns a category to the torrents identified by
// pipe-separated hashes. Returns 0 on success, -1 on error.
//
//export QbtSetTorrentCategory
func QbtSetTorrentCategory(h C.uintptr_t, hashes, category *C.char) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.SetTorrentCategory(splitPipe(hashes), goStr(category)))
}

// QbtSetTorrentName renames a torrent. Returns 0 on success, -1 on error.
//
//export QbtSetTorrentName
func QbtSetTorrentName(h C.uintptr_t, hash, name *C.char) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.SetTorrentName(goStr(hash), goStr(name)))
}

// QbtSetTorrentLocation sets the save path for pipe-separated hashes.
// Returns 0 on success, -1 on error.
//
//export QbtSetTorrentLocation
func QbtSetTorrentLocation(h C.uintptr_t, hashes, location *C.char) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.SetTorrentLocation(splitPipe(hashes), goStr(location)))
}

// ---------------------------------------------------------------------------
// Categories & tags
// ---------------------------------------------------------------------------

// QbtGetCategoriesJSON returns all categories as a malloc'd JSON object.
// Returns "" on error. Caller must free with QbtFreeString.
//
//export QbtGetCategoriesJSON
func QbtGetCategoriesJSON(h C.uintptr_t) *C.char {
	ctx := getCtx(h)
	cats, err := ctx.client.GetCategories()
	if err != nil {
		ctx.setErr(err)
		return C.CString("")
	}
	return marshalJSON(cats, ctx)
}

// QbtCreateCategory creates a category with an optional save path.
// Pass "" for savePath to use the default. Returns 0 on success, -1 on error.
//
//export QbtCreateCategory
func QbtCreateCategory(h C.uintptr_t, category, savePath *C.char) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.CreateCategory(goStr(category), goStr(savePath)))
}

// QbtDeleteCategories removes pipe-separated category names.
// Returns 0 on success, -1 on error.
//
//export QbtDeleteCategories
func QbtDeleteCategories(h C.uintptr_t, categories *C.char) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.DeleteCategories(splitPipe(categories)))
}

// QbtGetTagsJSON returns all tags as a malloc'd JSON array string.
// Returns "" on error. Caller must free with QbtFreeString.
//
//export QbtGetTagsJSON
func QbtGetTagsJSON(h C.uintptr_t) *C.char {
	ctx := getCtx(h)
	tags, err := ctx.client.GetTorrentTags()
	if err != nil {
		ctx.setErr(err)
		return C.CString("")
	}
	return marshalJSON(tags, ctx)
}

// QbtCreateTags creates comma-separated tags in the session.
// Returns 0 on success, -1 on error.
//
//export QbtCreateTags
func QbtCreateTags(h C.uintptr_t, tags *C.char) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.CreateTags(strings.Split(goStr(tags), ",")))
}

// QbtDeleteTags removes comma-separated tags from the session.
// Returns 0 on success, -1 on error.
//
//export QbtDeleteTags
func QbtDeleteTags(h C.uintptr_t, tags *C.char) C.int {
	ctx := getCtx(h)
	return ctx.setErr(ctx.client.DeleteTags(strings.Split(goStr(tags), ",")))
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

// QbtSyncMaindataJSON returns incremental main-view state as a malloc'd JSON
// string. Passing rid=0 continues from the last rid stored in the client.
// Returns "" on error. Caller must free with QbtFreeString.
//
//export QbtSyncMaindataJSON
func QbtSyncMaindataJSON(h C.uintptr_t, rid C.uint64_t) *C.char {
	ctx := getCtx(h)
	data, err := ctx.client.MainData(uint64(rid))
	if err != nil {
		ctx.setErr(err)
		return C.CString("")
	}
	return marshalJSON(data, ctx)
}
