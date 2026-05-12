package qbt

// Sync is api/v2/sync/maindata (SyncController::generateMaindataSyncData).
type Sync struct {
	Rid               uint64                 `json:"rid"`
	FullUpdate        bool                   `json:"full_update"`
	Torrents          map[string]TorrentInfo `json:"torrents"`
	TorrentsRemoved   []string               `json:"torrents_removed"`
	Categories        map[string]Category    `json:"categories"`
	CategoriesRemoved []string               `json:"categories_removed"`
	Tags              []string               `json:"tags"`
	TagsRemoved       []string               `json:"tags_removed"`
	Trackers          map[string][]string    `json:"trackers"`
	TrackersRemoved   []string               `json:"trackers_removed"`
	ServerState       ServerState            `json:"server_state"`
}

// ServerState is the single object under sync/maindata "server_state" (not an array).
type ServerState struct {
	AllTimeDL              int64  `json:"alltime_dl"`
	AllTimeUL              int64  `json:"alltime_ul"`
	AverageTimeQueue       int    `json:"average_time_queue"`
	ConnectionStatus       string `json:"connection_status"`
	DhtNodes               int64  `json:"dht_nodes"`
	DlInfoData             int64  `json:"dl_info_data"`
	DlInfoSpeed            int64  `json:"dl_info_speed"`
	DlRateLimit            int64  `json:"dl_rate_limit"`
	UpInfoData             int64  `json:"up_info_data"`
	UpInfoSpeed            int64  `json:"up_info_speed"`
	UpRateLimit            int64  `json:"up_rate_limit"`
	LastExternalAddressV4  string `json:"last_external_address_v4"`
	LastExternalAddressV6  string `json:"last_external_address_v6"`
	FreeSpaceOnDisk        int64  `json:"free_space_on_disk"`
	GlobalRatio            string `json:"global_ratio"`
	QueuedIoJobs           int    `json:"queued_io_jobs"`
	QueuedTrackerAnnounces int64  `json:"queued_tracker_announces"`
	RequestLatency         int64  `json:"request_latency"`
	Queueing               bool   `json:"queueing"`
	ReadCacheHits          string `json:"read_cache_hits"`
	ReadCacheOverload      string `json:"read_cache_overload"`
	WriteCacheOverload     string `json:"write_cache_overload"`
	RefreshInterval        int    `json:"refresh_interval"`
	TotalBuffersSize       int64  `json:"total_buffers_size"`
	TotalPeerConnections   int    `json:"total_peer_connections"`
	TotalQueuedSize        int64  `json:"total_queued_size"`
	TotalWastedSession     int64  `json:"total_wasted_session"`
	UseAltSpeedLimits      bool   `json:"use_alt_speed_limits"`
}

type TorrentPeers struct {
	FullUpdate bool            `json:"full_update"`
	Peers      map[string]Peer `json:"peers"`
	Rid        uint64          `json:"rid"`
	ShowFlags  bool            `json:"show_flags"`
}

type Peer struct {
	Client       string  `json:"client"`
	PeerIdClient string  `json:"peer_id_client"`
	Progress     float64 `json:"progress"`
	DlSpeed      int     `json:"dl_speed"`
	UpSpeed      int     `json:"up_speed"`
	Downloaded   int64   `json:"downloaded"`
	Uploaded     int64   `json:"uploaded"`
	Connection   string  `json:"connection"`
	Flags        string  `json:"flags"`
	FlagsDesc    string  `json:"flags_desc"`
	Relevance    int     `json:"relevance"`
	Files        string  `json:"files"`
	Ip           string  `json:"ip"`
	HostName     string  `json:"host_name"`
	I2PDest      string  `json:"i2p_dest"`
	Port         int     `json:"port"`
	Country      string  `json:"country"`
	CountryCode  string  `json:"country_code"`
}
