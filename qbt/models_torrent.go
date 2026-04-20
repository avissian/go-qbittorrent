package qbt

// Torrent is api/v2/torrents/properties (TorrentsController::propertiesAction).
type Torrent struct {
	Hash               string  `json:"hash"`
	InfohashV1         string  `json:"infohash_v1"`
	InfohashV2         string  `json:"infohash_v2"`
	Name               string  `json:"name"`
	TimeElapsed        int64   `json:"time_elapsed"`
	SeedingTime        int64   `json:"seeding_time"`
	Eta                int64   `json:"eta"`
	NbConnections      int     `json:"nb_connections"`
	NbConnectionsLimit int     `json:"nb_connections_limit"`
	TotalDownloaded    int64   `json:"total_downloaded"`
	TotalDlSession     int64   `json:"total_downloaded_session"`
	TotalUploaded      int64   `json:"total_uploaded"`
	TotalUlSession     int64   `json:"total_uploaded_session"`
	DlSpeed            int64   `json:"dl_speed"`
	DlSpeedAvg         int64   `json:"dl_speed_avg"`
	UpSpeed            int64   `json:"up_speed"`
	UpSpeedAvg         int64   `json:"up_speed_avg"`
	DlLimit            int64   `json:"dl_limit"`
	UpLimit            int64   `json:"up_limit"`
	TotalWasted        int64   `json:"total_wasted"`
	Seeds              int     `json:"seeds"`
	SeedsTotal         int     `json:"seeds_total"`
	Peers              int     `json:"peers"`
	PeersTotal         int     `json:"peers_total"`
	ShareRatio         float64 `json:"share_ratio"`
	Popularity         float64 `json:"popularity"`
	Availability       float64 `json:"availability"`
	Reannounce         int64   `json:"reannounce"`
	TotalSize          int64   `json:"total_size"`
	PiecesNum          int     `json:"pieces_num"`
	PieceSize          int64   `json:"piece_size"`
	PiecesHave         int     `json:"pieces_have"`
	CreatedBy          string  `json:"created_by"`
	IsPrivate          bool    `json:"is_private"`
	Private            *bool   `json:"private"`
	AdditionDate       int64   `json:"addition_date"`
	LastSeen           int64   `json:"last_seen"`
	CompletionDate     int64   `json:"completion_date"`
	CreationDate       int64   `json:"creation_date"`
	SavePath           string  `json:"save_path"`
	DownloadPath       string  `json:"download_path"`
	Comment            string  `json:"comment"`
	HasMetadata        bool    `json:"has_metadata"`
	Progress           float64 `json:"progress"`
}

// TorrentInfo is one entry from api/v2/torrents/info and sync/maindata torrents
// (see serialize() in serialize/serialize_torrent.cpp). Extra keys may appear in sync diffs only.
type TorrentInfo struct {
	Hash                     string  `json:"hash"`
	InfohashV1               string  `json:"infohash_v1"`
	InfohashV2               string  `json:"infohash_v2"`
	Name                     string  `json:"name"`
	HasMetadata              bool    `json:"has_metadata"`
	CreatedBy                string  `json:"created_by"`
	CreationDate             int64   `json:"creation_date"`
	Private                  *bool   `json:"private"`
	TotalSize                int64   `json:"total_size"`
	PiecesNum                int     `json:"pieces_num"`
	PieceSize                int64   `json:"piece_size"`
	MagnetURI                string  `json:"magnet_uri"`
	Size                     int64   `json:"size"`
	Progress                 float64 `json:"progress"`
	TotalWasted              int64   `json:"total_wasted"`
	PiecesHave               int     `json:"pieces_have"`
	Dlspeed                  int64   `json:"dlspeed"`
	Upspeed                  int64   `json:"upspeed"`
	Priority                 int     `json:"priority"`
	NumSeeds                 int     `json:"num_seeds"`
	NumComplete              int64   `json:"num_complete"`
	NumLeechs                int     `json:"num_leechs"`
	NumIncomplete            int64   `json:"num_incomplete"`
	State                    string  `json:"state"`
	Eta                      int64   `json:"eta"`
	SeqDl                    bool    `json:"seq_dl"`
	FLPiecePrio              bool    `json:"f_l_piece_prio"`
	Category                 string  `json:"category"`
	Tags                     string  `json:"tags"`
	SuperSeeding             bool    `json:"super_seeding"`
	ForceStart               bool    `json:"force_start"`
	SavePath                 string  `json:"save_path"`
	DownloadPath             string  `json:"download_path"`
	ContentPath              string  `json:"content_path"`
	RootPath                 string  `json:"root_path"`
	AddedOn                  int64   `json:"added_on"`
	CompletionOn             int64   `json:"completion_on"`
	Tracker                  string  `json:"tracker"`
	TrackersCount            int     `json:"trackers_count"`
	DlLimit                  int64   `json:"dl_limit"`
	UpLimit                  int64   `json:"up_limit"`
	Downloaded               int64   `json:"downloaded"`
	Uploaded                 int64   `json:"uploaded"`
	DownloadedSession        int64   `json:"downloaded_session"`
	UploadedSession          int64   `json:"uploaded_session"`
	AmountLeft               int64   `json:"amount_left"`
	Completed                int64   `json:"completed"`
	ConnectionsCount         int     `json:"connections_count"`
	ConnectionsLimit         int     `json:"connections_limit"`
	MaxRatio                 float64 `json:"max_ratio"`
	MaxSeedingTime           int64   `json:"max_seeding_time"`
	MaxInactiveSeedingTime   int64   `json:"max_inactive_seeding_time"`
	Ratio                    float64 `json:"ratio"`
	RatioLimit               float64 `json:"ratio_limit"`
	Popularity               float64 `json:"popularity"`
	SeedingTimeLimit         int64   `json:"seeding_time_limit"`
	InactiveSeedingTimeLimit int64   `json:"inactive_seeding_time_limit"`
	ShareLimitsMode          string  `json:"share_limits_mode"`
	ShareLimitAction         string  `json:"share_limit_action"`
	SeenComplete             int64   `json:"seen_complete"`
	AutoTmm                  bool    `json:"auto_tmm"`
	TimeActive               int64   `json:"time_active"`
	SeedingTime              int64   `json:"seeding_time"`
	LastActivity             int64   `json:"last_activity"`
	Availability             float64 `json:"availability"`
	Reannounce               int64   `json:"reannounce"`
	Comment                  string  `json:"comment"`
	HasTrackerWarning        bool    `json:"has_tracker_warning"`
	HasTrackerError          bool    `json:"has_tracker_error"`
	HasOtherAnnounceError    bool    `json:"has_other_announce_error"`
}

// TrackerEndpoint is one element of tracker "endpoints" (TorrentsController::getTrackers).
type TrackerEndpoint struct {
	Name          string `json:"name"`
	Updating      bool   `json:"updating"`
	Status        int    `json:"status"`
	Msg           string `json:"msg"`
	BtVersion     int    `json:"bt_version"`
	NumPeers      int    `json:"num_peers"`
	NumSeeds      int    `json:"num_seeds"`
	NumLeeches    int    `json:"num_leeches"`
	NumDownloaded int    `json:"num_downloaded"`
	NextAnnounce  int64  `json:"next_announce"`
	MinAnnounce   int64  `json:"min_announce"`
}

// Tracker is one tracker row from api/v2/torrents/trackers.
type Tracker struct {
	URL           string            `json:"url"`
	Tier          int               `json:"tier"`
	Updating      bool              `json:"updating"`
	Status        int               `json:"status"`
	Msg           string            `json:"msg"`
	NumPeers      int               `json:"num_peers"`
	NumSeeds      int               `json:"num_seeds"`
	NumLeeches    int               `json:"num_leeches"`
	NumDownloaded int               `json:"num_downloaded"`
	NextAnnounce  int64             `json:"next_announce"`
	MinAnnounce   int64             `json:"min_announce"`
	Endpoints     []TrackerEndpoint `json:"endpoints"`
}

// WebSeed is one HTTP(S) web seed URL for a torrent.
type WebSeed struct {
	URL string `json:"url"`
}

// TorrentFile is one entry from api/v2/torrents/files (TorrentsController::getFiles).
type TorrentFile struct {
	Index        int     `json:"index"`
	Name         string  `json:"name"`
	Size         int64   `json:"size"`
	Progress     float64 `json:"progress"`
	Priority     int     `json:"priority"`
	IsSeed       bool    `json:"is_seed"`
	PieceRange   []int   `json:"piece_range"`
	Availability float64 `json:"availability"`
}

// TorrentSSLParameters from api/v2/torrents/SSLParameters and setSSLParameters.
type TorrentSSLParameters struct {
	SSLCertificate string `json:"ssl_certificate"`
	SSLPrivateKey  string `json:"ssl_private_key"`
	SSLDhParams    string `json:"ssl_dh_params"`
}

// AddPeersResult is the per-torrent object from api/v2/torrents/addPeers.
type AddPeersResult struct {
	Added  int `json:"added"`
	Failed int `json:"failed"`
}
