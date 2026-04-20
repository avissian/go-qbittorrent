# `qbt.Client` methods

Short index of the public API. Implementations live in the [`qbt`](qbt/) package; the file name in parentheses is the usual location.

## Constructor

| Method | Description |
|--------|-------------|
| `NewClient(url string) *Client` (`client.go`) | Connect to the Web UI (base URL should end with `/`). |

## Authentication (`auth.go`)

| Method | Description |
|--------|-------------|
| `Login(LoginOptions) error` | Sign in; session cookie is stored in the jar. |
| `Logout() error` | Sign out. |

## Application (`app.go`)

| Method | Description |
|--------|-------------|
| `ApplicationVersion() (string, error)` | qBittorrent application version. |
| `WebAPIVersion() (string, error)` | Web API version string. |
| `BuildInfo() (BuildInfo, error)` | Build metadata (Qt, libtorrent, etc.). |
| `Preferences() (Preferences, error)` | Settings decoded into `Preferences`. |
| `PreferencesRaw() (string, error)` | Raw preferences JSON. |
| `SetPreferences(map[string]any) error` | Save settings. |
| `DefaultSavePath() (string, error)` | Default save path. |
| `Shutdown() error` | Shut down the application. |
| `ProcessInfo() (ProcessInfo, error)` | Process-related info. |
| `SendTestEmail() error` | Send a test email (if mail is configured). |
| `GetDirectoryContent(...) (json.RawMessage, error)` | Directory listing. |
| `GetFreeSpaceAtPath(string) (int64, error)` | Free disk space at path. |
| `Cookies() ([]AppCookie, error)` | Internal downloader HTTP cookies. |
| `SetCookies(string) error` | Set cookies (JSON). |
| `RotateAPIKey() (string, error)` | Rotate Web UI API key. |
| `DeleteAPIKey() error` | Delete Web UI API key. |
| `NetworkInterfaceList() ([]NetworkInterface, error)` | Network interfaces. |
| `NetworkInterfaceAddressList(string) ([]string, error)` | IP addresses for an interface. |

## Logs (`log.go`)

| Method | Description |
|--------|-------------|
| `Logs(map[string]string) ([]Log, error)` | Main application log. |
| `PeerLogs(map[string]string) ([]PeerLog, error)` | Peer log. |

## Transfer (`transfer.go`)

| Method | Description |
|--------|-------------|
| `Info(InfoOptions) (Info, error)` | Session summary (speeds, limits, DHT, etc.). |
| `AltSpeedLimitsEnabled() (bool, error)` | Whether alternative speed limits are on. |
| `ToggleAltSpeedLimits() error` | Toggle alternative speed limits. |
| `SetSpeedLimitsMode(int) error` | Set alternative speed limits mode explicitly. |
| `DlLimit() (int, error)` / `SetDlLimit(int) error` | Global download limit. |
| `UlLimit() (int, error)` / `SetUlLimit(int) error` | Global upload limit. |
| `BanPeers([]string) error` | Ban peers by address list. |

## Torrents — core (`torrents.go`)

| Method | Description |
|--------|-------------|
| `Torrents(TorrentsOptions) ([]TorrentInfo, error)` | Torrent list with filters. |
| `Torrent(string) (Torrent, error)` | Properties for one torrent. |
| `TorrentTrackers` / `TorrentWebSeeds` / `TorrentFiles` | Trackers, web seeds, files. |
| `TorrentPieceStates` / `TorrentPieceHashes` | Piece states and hashes. |
| `Pause` / `Resume` / `Delete` / `Recheck` / `Reannounce` | State control. |
| `DownloadLinks` / `DownloadFromFile` | Add by URL or from `.torrent` (multipart). |
| `AddTrackers` / `EditTracker` / `RemoveTrackers` | Tracker management. |
| `IncreasePriority` / `DecreasePriority` / `MaxPriority` / `MinPriority` | Queue position. |
| `FilePriority` | Per-file priority. |
| `GetTorrentDownloadLimit` / `SetTorrentDownloadLimit` | Per-torrent download limits. |
| `GetTorrentUploadLimit` / `SetTorrentUploadLimit` | Per-torrent upload limits. |
| `SetTorrentShareLimit` | Ratio / seeding time limits. |
| `SetTorrentLocation` / `SetTorrentName` | Save path and display name. |
| `GetCategories` / `CreateCategory` / `UpdateCategory` / `DeleteCategories` | Categories. |
| `SetTorrentCategory` | Assign category to torrents. |
| `AddTorrentTags` / `RemoveTorrentTags` / `GetTorrentTags` / `CreateTags` / `DeleteTags` | Tags. |
| `SetAutoManagement` | Automatic torrent management (TMM). |
| `ToggleSequentialDownload` / `ToggleFirstLastPiecePriority` | Sequential download and first/last piece priority. |
| `SetForceStart` / `SetSuperSeeding` | Force start and super seeding. |

## Torrents — extended (`torrents_extended.go`)

| Method | Description |
|--------|-------------|
| `TorrentsCount() (int, error)` | Number of torrents in the session. |
| `TorrentPieceAvailability(string) ([]int, error)` | Per-piece availability. |
| `AddWebSeeds` / `EditWebSeed` / `RemoveWebSeeds` | HTTP(S) web seeds. |
| `AddPeers` | Manually add peers. |
| `SetTorrentSavePath` / `SetTorrentDownloadPath` | Content and download paths. |
| `SetTorrentComment` / `SetTorrentTags` | Comment and full tag set for torrents. |
| `RenameTorrentFile` / `RenameTorrentFolder` | Rename inside multi-file torrents. |
| `ExportTorrent(string) ([]byte, error)` | Export `.torrent` bytes. |
| `TorrentSSLParameters` / `SetTorrentSSLParameters` | SSL parameters for a torrent. |
| `FetchTorrentMetadata` | Resolve/fetch metadata (may return 202 while pending). |
| `ParseTorrentMetadata` | Parse local `.torrent` paths via the API. |
| `SaveTorrentMetadata` | Save metadata for a source. |

## Web UI sync (`sync.go`)

| Method | Description |
|--------|-------------|
| `TorrentPeers(string, uint64) (TorrentPeers, error)` | Peers for one torrent (`rid`). |
| `MainData(uint64) (Sync, error)` | Incremental main view state (`rid`). |

## Client data (`clientdata.go`)

| Method | Description |
|--------|-------------|
| `ClientDataLoad([]string) (json.RawMessage, error)` | Load Web UI client data by keys. |
| `ClientDataStore(string) error` | Store client data JSON. |

## Torrent creator (`torrentcreator.go`)

| Method | Description |
|--------|-------------|
| `TorrentCreatorAddTask(TorrentCreatorAddTaskOptions) (string, error)` | Enqueue a torrent creation job. |
| `TorrentCreatorStatus(string) ([]TorrentCreatorTaskStatus, error)` | Task status (empty id = all tasks). |
| `TorrentCreatorTorrentFile(string) ([]byte, error)` | Download finished `.torrent` bytes. |
| `TorrentCreatorDeleteTask(string) error` | Remove a creation task. |

---

**Not covered by this wrapper:** RSS, search, and any other endpoints omitted above. For version requirements, see the [official Web API documentation](https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1)).
