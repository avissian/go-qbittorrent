go-qbittorrent
==============

Go client for the qBittorrent Web API (v4.1+), forked from
[superturkey650/go-qbittorrent](https://github.com/superturkey650/go-qbittorrent).

Supports qBittorrent through the current **5.2.0** release (Web API 2.16.0).
Backwards-compatible with older servers — version-specific behaviour is
detected automatically at runtime.

- API reference: [WebUI API (qBittorrent 4.1)](https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1)) and the [WebAPI_Changelog](https://github.com/qbittorrent/qBittorrent/blob/master/WebAPI_Changelog.md)
- Method index: [METHODS.md](METHODS.md)
- Quick start sample: [`example/`](example/)

---

## Go library

### Installation

```
go get github.com/avissian/go-qbittorrent/qbt
```

### Usage

```go
import "github.com/avissian/go-qbittorrent/qbt"

client := qbt.NewClient("http://127.0.0.1:8080/")

if err := client.Login(qbt.LoginOptions{Username: "admin", Password: "adminadmin"}); err != nil {
    log.Fatal(err)
}
defer client.Logout()

torrents, err := client.Torrents(qbt.TorrentsOptions{})
if err != nil {
    log.Fatal(err)
}
for _, t := range torrents {
    fmt.Println(t.Name, t.State)
}
```

---

## C shared library

The `clib/` package compiles the client into a C-compatible shared library
(`libqbt.so` / `libqbt.dylib` / `libqbt.dll`) so it can be called from C,
C++, Python (ctypes/cffi), Rust (bindgen), or any other language with a C FFI.

### Download pre-built binaries

Pre-built archives for every supported platform are attached to each
[GitHub Release](../../releases). Each archive contains the shared library
and the matching `libqbt.h` header.

| Archive | Platform |
|---|---|
| `libqbt-linux-amd64.tar.gz` | Linux x86-64 |
| `libqbt-linux-arm64.tar.gz` | Linux ARM64 |
| `libqbt-darwin-arm64.tar.gz` | macOS Apple Silicon (native) |
| `libqbt-darwin-amd64.tar.gz` | macOS Intel / Rosetta 2 |
| `libqbt-windows-amd64.zip` | Windows x86-64 |

### Build from source

Requires Go 1.21+ and a C compiler (`gcc` / `clang` / MinGW on Windows).

```bash
# current platform
make

# explicit platform (cross-compilation)
make linux    # → dist/libqbt.so
make darwin   # → dist/libqbt.dylib
make windows  # → dist/libqbt.dll  (needs x86_64-w64-mingw32-gcc)
```

Or invoke `go build` directly:

```bash
go build -buildmode=c-shared -o libqbt.so    ./clib/   # Linux
go build -buildmode=c-shared -o libqbt.dylib ./clib/   # macOS
go build -buildmode=c-shared -o libqbt.dll   ./clib/   # Windows
```

The build also emits a `libqbt.h` header next to the library file.

### C API overview

All functions share a common handle-based pattern.

#### Handle lifecycle

```c
// Create a client for the given Web UI URL.
uintptr_t h = QbtNewClient("http://127.0.0.1:8080/");

// … use the client …

// Release all resources. Do not use h after this call.
QbtFreeClient(h);
```

#### String ownership

Every function that returns `char*` allocates a new heap string.
**The caller must release it with `QbtFreeString()`.**

```c
char *ver = QbtAppVersion(h);
printf("qBittorrent %s\n", ver);
QbtFreeString(ver);
```

#### Error handling

Mutator functions return `int` — `0` on success, `-1` on error.
Query functions return `""` (empty string) on error.
In both cases call `QbtLastError()` to retrieve the message:

```c
if (QbtPause(h, "abc123|def456") != 0) {
    char *err = QbtLastError(h);
    fprintf(stderr, "error: %s\n", err);
    QbtFreeString(err);
}
```

#### Complete example

```c
#include <stdio.h>
#include "libqbt.h"

int main(void) {
    uintptr_t h = QbtNewClient("http://127.0.0.1:8080/");

    if (QbtLogin(h, "admin", "adminadmin") != 0) {
        char *err = QbtLastError(h);
        fprintf(stderr, "login failed: %s\n", err);
        QbtFreeString(err);
        QbtFreeClient(h);
        return 1;
    }

    /* List all torrents as JSON */
    char *json = QbtTorrentsJSON(h, NULL, NULL, NULL, 0, 0, 0);
    printf("%s\n", json);
    QbtFreeString(json);

    /* Pause two torrents */
    QbtPause(h, "aabbcc|ddeeff");

    /* Add a magnet link */
    char *result = QbtDownloadLinks(
        h,
        "magnet:?xt=urn:btih:…",
        "/tmp/downloads",   /* save path  (NULL = default) */
        "Movies"            /* category   (NULL = none)    */
    );
    QbtFreeString(result);

    QbtLogout(h);
    QbtFreeClient(h);
    return 0;
}
```

Compile:

```bash
# Linux
gcc example.c -L. -lqbt -Wl,-rpath,'$ORIGIN' -o example

# macOS
clang example.c -L. -lqbt -o example

# Windows (MinGW)
gcc example.c -L. -lqbt -o example.exe
```

### Full API reference

#### Lifecycle & errors

| Function | Returns | Description |
|---|---|---|
| `QbtNewClient(url)` | `uintptr_t` | Create client, return handle |
| `QbtFreeClient(h)` | `void` | Destroy client |
| `QbtLastError(h)` | `char*` | Last error message (free with `QbtFreeString`) |
| `QbtFreeString(s)` | `void` | Release any `char*` returned by this library |

#### Authentication

| Function | Returns | Description |
|---|---|---|
| `QbtLogin(h, user, pass)` | `int` | Login |
| `QbtLogout(h)` | `int` | Logout |

#### Application

| Function | Returns | Description |
|---|---|---|
| `QbtAppVersion(h)` | `char*` | Application version string |
| `QbtWebAPIVersion(h)` | `char*` | Web API version string |
| `QbtPreferencesJSON(h)` | `char*` | All preferences as JSON |
| `QbtDefaultSavePath(h)` | `char*` | Default save directory |

#### Transfer

| Function | Returns | Description |
|---|---|---|
| `QbtTransferInfoJSON(h)` | `char*` | Global transfer statistics as JSON |
| `QbtSetDlLimit(h, limit)` | `int` | Global download limit, bytes/s (0 = unlimited) |
| `QbtSetUlLimit(h, limit)` | `int` | Global upload limit, bytes/s (0 = unlimited) |

#### Torrents — listing

| Function | Returns | Description |
|---|---|---|
| `QbtTorrentsJSON(h, filter, category, sort, reverse, limit, offset)` | `char*` | Torrent list as JSON array. Pass `NULL`/`""` to omit optional params; `reverse=1` for descending sort |
| `QbtTorrentJSON(h, hash)` | `char*` | Single torrent properties as JSON |
| `QbtTorrentTrackersJSON(h, hash)` | `char*` | Tracker list as JSON array |

#### Torrents — control

| Function | Returns | Description |
|---|---|---|
| `QbtPause(h, hashes)` | `int` | Pause; `hashes` = pipe-separated, or `"all"` |
| `QbtResume(h, hashes)` | `int` | Resume |
| `QbtDelete(h, hashes, deleteFiles)` | `int` | Delete; `deleteFiles=1` removes data |
| `QbtRecheck(h, hashes)` | `int` | Force data integrity check |
| `QbtReannounce(h, hashes)` | `int` | Re-announce to trackers |

#### Torrents — adding

| Function | Returns | Description |
|---|---|---|
| `QbtDownloadLinks(h, urls, savePath, category)` | `char*` | Add from newline-separated magnet/HTTP URLs. Returns add-result JSON |
| `QbtDownloadFromFile(h, filePath, savePath, category)` | `char*` | Add from a local `.torrent` file. Returns add-result JSON |

#### Torrents — properties

| Function | Returns | Description |
|---|---|---|
| `QbtSetTorrentDownloadLimit(h, hashes, limit)` | `int` | Per-torrent download limit, bytes/s |
| `QbtSetTorrentUploadLimit(h, hashes, limit)` | `int` | Per-torrent upload limit, bytes/s |
| `QbtSetTorrentCategory(h, hashes, category)` | `int` | Assign category |
| `QbtSetTorrentName(h, hash, name)` | `int` | Rename torrent |
| `QbtSetTorrentLocation(h, hashes, location)` | `int` | Set save path |

#### Categories & tags

| Function | Returns | Description |
|---|---|---|
| `QbtGetCategoriesJSON(h)` | `char*` | All categories as JSON object |
| `QbtCreateCategory(h, name, savePath)` | `int` | Create category |
| `QbtDeleteCategories(h, names)` | `int` | Delete pipe-separated categories |
| `QbtGetTagsJSON(h)` | `char*` | All tags as JSON array |
| `QbtCreateTags(h, tags)` | `int` | Create comma-separated tags |
| `QbtDeleteTags(h, tags)` | `int` | Delete comma-separated tags |

#### Sync

| Function | Returns | Description |
|---|---|---|
| `QbtSyncMaindataJSON(h, rid)` | `char*` | Incremental main-data state as JSON. Pass `0` to continue from last stored `rid` |
