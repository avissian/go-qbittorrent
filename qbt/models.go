package qbt

/**
API v2.9.3 (qBittorrent 4.6.2)
https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1)#api-v283
*/

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
	Hash                       string  `json:"hash"`
	InfohashV1                 string  `json:"infohash_v1"`
	InfohashV2                 string  `json:"infohash_v2"`
	Name                       string  `json:"name"`
	HasMetadata                bool    `json:"has_metadata"`
	CreatedBy                  string  `json:"created_by"`
	CreationDate               int64   `json:"creation_date"`
	Private                    *bool   `json:"private"`
	TotalSize                  int64   `json:"total_size"`
	PiecesNum                  int     `json:"pieces_num"`
	PieceSize                  int64   `json:"piece_size"`
	MagnetURI                  string  `json:"magnet_uri"`
	Size                       int64   `json:"size"`
	Progress                   float64 `json:"progress"`
	TotalWasted                int64   `json:"total_wasted"`
	PiecesHave                 int     `json:"pieces_have"`
	Dlspeed                    int64   `json:"dlspeed"`
	Upspeed                    int64   `json:"upspeed"`
	Priority                   int     `json:"priority"`
	NumSeeds                   int     `json:"num_seeds"`
	NumComplete                int64   `json:"num_complete"`
	NumLeechs                  int     `json:"num_leechs"`
	NumIncomplete              int64   `json:"num_incomplete"`
	State                      string  `json:"state"`
	Eta                        int64   `json:"eta"`
	SeqDl                      bool    `json:"seq_dl"`
	FLPiecePrio                bool    `json:"f_l_piece_prio"`
	Category                   string  `json:"category"`
	Tags                       string  `json:"tags"`
	SuperSeeding               bool    `json:"super_seeding"`
	ForceStart                 bool    `json:"force_start"`
	SavePath                   string  `json:"save_path"`
	DownloadPath               string  `json:"download_path"`
	ContentPath                string  `json:"content_path"`
	RootPath                   string  `json:"root_path"`
	AddedOn                    int64   `json:"added_on"`
	CompletionOn               int64   `json:"completion_on"`
	Tracker                    string  `json:"tracker"`
	TrackersCount              int     `json:"trackers_count"`
	DlLimit                    int64   `json:"dl_limit"`
	UpLimit                    int64   `json:"up_limit"`
	Downloaded                 int64   `json:"downloaded"`
	Uploaded                   int64   `json:"uploaded"`
	DownloadedSession          int64   `json:"downloaded_session"`
	UploadedSession            int64   `json:"uploaded_session"`
	AmountLeft                 int64   `json:"amount_left"`
	Completed                  int64   `json:"completed"`
	ConnectionsCount           int     `json:"connections_count"`
	ConnectionsLimit           int     `json:"connections_limit"`
	MaxRatio                   float64 `json:"max_ratio"`
	MaxSeedingTime             int64   `json:"max_seeding_time"`
	MaxInactiveSeedingTime     int64   `json:"max_inactive_seeding_time"`
	Ratio                      float64 `json:"ratio"`
	RatioLimit                 float64 `json:"ratio_limit"`
	Popularity                 float64 `json:"popularity"`
	SeedingTimeLimit           int64   `json:"seeding_time_limit"`
	InactiveSeedingTimeLimit   int64   `json:"inactive_seeding_time_limit"`
	ShareLimitsMode            string  `json:"share_limits_mode"`
	ShareLimitAction           string  `json:"share_limit_action"`
	SeenComplete               int64   `json:"seen_complete"`
	AutoTmm                    bool    `json:"auto_tmm"`
	TimeActive                 int64   `json:"time_active"`
	SeedingTime                int64   `json:"seeding_time"`
	LastActivity               int64   `json:"last_activity"`
	Availability               float64 `json:"availability"`
	Reannounce                 int64   `json:"reannounce"`
	Comment                    string  `json:"comment"`
	HasTrackerWarning     bool `json:"has_tracker_warning"`
	HasTrackerError       bool `json:"has_tracker_error"`
	HasOtherAnnounceError bool `json:"has_other_announce_error"`
}

// TrackerEndpoint is one element of tracker "endpoints" (TorrentsController::getTrackers).
type TrackerEndpoint struct {
	Name           string `json:"name"`
	Updating       bool   `json:"updating"`
	Status         int    `json:"status"`
	Msg            string `json:"msg"`
	BtVersion      int    `json:"bt_version"`
	NumPeers       int    `json:"num_peers"`
	NumSeeds       int    `json:"num_seeds"`
	NumLeeches     int    `json:"num_leeches"`
	NumDownloaded  int    `json:"num_downloaded"`
	NextAnnounce   int64  `json:"next_announce"`
	MinAnnounce    int64  `json:"min_announce"`
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

// WebSeed holds a webseed object from qbittorrent
type WebSeed struct {
	URL string `json:"url"`
}

// TorrentFile is one entry from api/v2/torrents/files (TorrentsController::getFiles).
type TorrentFile struct {
	Index          int       `json:"index"`
	Name           string    `json:"name"`
	Size           int64     `json:"size"`
	Progress       float64   `json:"progress"`
	Priority       int       `json:"priority"`
	IsSeed         bool      `json:"is_seed"`
	PieceRange     []int     `json:"piece_range"`
	Availability   float64   `json:"availability"`
}

// Sync is api/v2/sync/maindata (SyncController::generateMaindataSyncData).
type Sync struct {
	Rid               uint64                 `json:"rid"`
	FullUpdate        bool                   `json:"full_update"`
	Torrents          map[string]TorrentInfo `json:"torrents"`
	TorrentsRemoved   []string               `json:"torrents_removed"`
	Categories          map[string]Category    `json:"categories"`
	CategoriesRemoved   []string               `json:"categories_removed"`
	Tags              []string               `json:"tags"`
	TagsRemoved       []string               `json:"tags_removed"`
	Trackers          map[string][]string    `json:"trackers"`
	TrackersRemoved   []string               `json:"trackers_removed"`
	ServerState       ServerState            `json:"server_state"`
}

// ServerState is the single object under sync/maindata "server_state" (not an array).
type ServerState struct {
	AllTimeDL               int64  `json:"alltime_dl"`
	AllTimeUL               int64  `json:"alltime_ul"`
	AverageTimeQueue        int    `json:"average_time_queue"`
	ConnectionStatus        string `json:"connection_status"`
	DhtNodes                int64  `json:"dht_nodes"`
	DlInfoData              int64  `json:"dl_info_data"`
	DlInfoSpeed             int64  `json:"dl_info_speed"`
	DlRateLimit             int64  `json:"dl_rate_limit"`
	UpInfoData              int64  `json:"up_info_data"`
	UpInfoSpeed             int64  `json:"up_info_speed"`
	UpRateLimit             int64  `json:"up_rate_limit"`
	LastExternalAddressV4   string `json:"last_external_address_v4"`
	LastExternalAddressV6   string `json:"last_external_address_v6"`
	FreeSpaceOnDisk         int64  `json:"free_space_on_disk"`
	GlobalRatio             string `json:"global_ratio"`
	QueuedIoJobs            int    `json:"queued_io_jobs"`
	QueuedTrackerAnnounces  int64  `json:"queued_tracker_announces"`
	Queueing                bool   `json:"queueing"`
	ReadCacheHits           string `json:"read_cache_hits"`
	ReadCacheOverload       string `json:"read_cache_overload"`
	WriteCacheOverload      string `json:"write_cache_overload"`
	RefreshInterval         int    `json:"refresh_interval"`
	TotalBuffersSize        int64  `json:"total_buffers_size"`
	TotalPeerConnections    int    `json:"total_peer_connections"`
	TotalQueuedSize         int64  `json:"total_queued_size"`
	TotalWastedSession      int64  `json:"total_wasted_session"`
	UseAltSpeedLimits       bool   `json:"use_alt_speed_limits"`
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

type BuildInfo struct {
	QTVersion         string `json:"qt"`
	LibtorrentVersion string `json:"libtorrent"`
	BoostVersion      string `json:"boost"`
	OpenSSLVersion    string `json:"openssl"`
	AppBitness        int    `json:"bitness"`
	ZLib              string `json:"zlib"`
}

// Preferences mirrors api/v2/app/preferences (see qBittorrent AppController::preferencesAction).
// Removed stale keys that never appear in that response (e.g. public_trackers, start_paused_enabled).
// ScanDirs values may be numbers or strings per watched-folder encoding — use map[string]interface{}.
type Preferences struct {
	AddStoppedEnabled               bool                   `json:"add_stopped_enabled"`
	AddToTopOfQueue                 bool                   `json:"add_to_top_of_queue"`
	AddTrackers                     string                 `json:"add_trackers"`
	AddTrackersEnabled              bool                   `json:"add_trackers_enabled"`
	AddTrackersFromURLEnabled       bool                   `json:"add_trackers_from_url_enabled"`
	AddTrackersURL                  string                 `json:"add_trackers_url"`
	AddTrackersURLList              string                 `json:"add_trackers_url_list"`
	AltDlLimit                      int                    `json:"alt_dl_limit"`
	AltUpLimit                      int                    `json:"alt_up_limit"`
	AlternativeWebuiEnabled         bool                   `json:"alternative_webui_enabled"`
	AlternativeWebuiPath            string                 `json:"alternative_webui_path"`
	AnnounceIP                      string                 `json:"announce_ip"`
	AnnouncePort                    int                    `json:"announce_port"`
	AnnounceToAllTiers              bool                   `json:"announce_to_all_tiers"`
	AnnounceToAllTrackers           bool                   `json:"announce_to_all_trackers"`
	AnonymousMode                   bool                   `json:"anonymous_mode"`
	AppInstanceName                 string                 `json:"app_instance_name"`
	AsyncIoThreads                  int                    `json:"async_io_threads"`
	AutoDeleteMode                  int                    `json:"auto_delete_mode"`
	AutoTmmEnabled                  bool                   `json:"auto_tmm_enabled"`
	AutorunEnabled                  bool                   `json:"autorun_enabled"`
	AutorunOnTorrentAddedEnabled    bool                   `json:"autorun_on_torrent_added_enabled"`
	AutorunOnTorrentAddedProgram    string                 `json:"autorun_on_torrent_added_program"`
	AutorunProgram                  string                 `json:"autorun_program"`
	BannedIPs                       string                 `json:"banned_IPs"`
	BdecodeDepthLimit               int                    `json:"bdecode_depth_limit"`
	BdecodeTokenLimit               int                    `json:"bdecode_token_limit"`
	BittorrentProtocol              int                    `json:"bittorrent_protocol"`
	BlockPeersOnPrivilegedPorts     bool                   `json:"block_peers_on_privileged_ports"`
	BypassAuthSubnetWhitelist       string                 `json:"bypass_auth_subnet_whitelist"`
	BypassAuthSubnetWhitelistEnabled bool                  `json:"bypass_auth_subnet_whitelist_enabled"`
	BypassLocalAuth                 bool                   `json:"bypass_local_auth"`
	CategoryChangedTmmEnabled       bool                   `json:"category_changed_tmm_enabled"`
	CheckingMemoryUse               int                    `json:"checking_memory_use"`
	ConfirmTorrentDeletion          bool                   `json:"confirm_torrent_deletion"`
	ConfirmTorrentRecheck           bool                   `json:"confirm_torrent_recheck"`
	ConnectionSpeed                 int                    `json:"connection_speed"`
	CurrentInterfaceAddress         string                 `json:"current_interface_address"`
	CurrentInterfaceName            string                 `json:"current_interface_name"`
	CurrentNetworkInterface         string                 `json:"current_network_interface"`
	DeleteTorrentContentFiles       bool                   `json:"delete_torrent_content_files"`
	Dht                             bool                   `json:"dht"`
	DhtBootstrapNodes               string                 `json:"dht_bootstrap_nodes"`
	DiskCache                       int                    `json:"disk_cache"`
	DiskCacheTtl                    int                    `json:"disk_cache_ttl"`
	DiskIoReadMode                  int                    `json:"disk_io_read_mode"`
	DiskIoType                      int                    `json:"disk_io_type"`
	DiskIoWriteMode                 int                    `json:"disk_io_write_mode"`
	DiskQueueSize                   int                    `json:"disk_queue_size"`
	DlLimit                         int                    `json:"dl_limit"`
	DontCountSlowTorrents           bool                   `json:"dont_count_slow_torrents"`
	DyndnsDomain                    string                 `json:"dyndns_domain"`
	DyndnsEnabled                   bool                   `json:"dyndns_enabled"`
	DyndnsPassword                  string                 `json:"dyndns_password"`
	DyndnsService                   int                    `json:"dyndns_service"`
	DyndnsUsername                  string                 `json:"dyndns_username"`
	EmbeddedTrackerPort             int                    `json:"embedded_tracker_port"`
	EmbeddedTrackerPortForwarding   bool                   `json:"embedded_tracker_port_forwarding"`
	EnableCoalesceReadWrite         bool                   `json:"enable_coalesce_read_write"`
	EnableEmbeddedTracker           bool                   `json:"enable_embedded_tracker"`
	EnableMultiConnectionsFromSameIp bool                  `json:"enable_multi_connections_from_same_ip"`
	EnablePieceExtentAffinity       bool                   `json:"enable_piece_extent_affinity"`
	EnableUploadSuggestions         bool                   `json:"enable_upload_suggestions"`
	Encryption                      int                    `json:"encryption"`
	ExcludedFileNames               string                 `json:"excluded_file_names"`
	ExcludedFileNamesEnabled        bool                   `json:"excluded_file_names_enabled"`
	ExportDir                       string                 `json:"export_dir"`
	ExportDirFin                    string                 `json:"export_dir_fin"`
	FileLogAge                      int                    `json:"file_log_age"`
	FileLogAgeType                  int                    `json:"file_log_age_type"`
	FileLogBackupEnabled            bool                   `json:"file_log_backup_enabled"`
	FileLogDeleteOld                bool                   `json:"file_log_delete_old"`
	FileLogEnabled                  bool                   `json:"file_log_enabled"`
	FileLogMaxSize                  int                    `json:"file_log_max_size"`
	FileLogPath                     string                 `json:"file_log_path"`
	FilePoolSize                    int                    `json:"file_pool_size"`
	HashingThreads                  int                    `json:"hashing_threads"`
	HostnameCacheTTL                int                    `json:"hostname_cache_ttl"`
	I2PAddress                      string                 `json:"i2p_address"`
	I2PEnabled                      bool                   `json:"i2p_enabled"`
	I2PInboundLength                int                    `json:"i2p_inbound_length"`
	I2PInboundQuantity              int                    `json:"i2p_inbound_quantity"`
	I2PMixedMode                    bool                   `json:"i2p_mixed_mode"`
	I2POutboundLength               int                    `json:"i2p_outbound_length"`
	I2POutboundQuantity             int                    `json:"i2p_outbound_quantity"`
	I2PPort                         int                    `json:"i2p_port"`
	IdnSupportEnabled               bool                   `json:"idn_support_enabled"`
	IgnoreSSLErrors                 bool                   `json:"ignore_ssl_errors"`
	IncompleteFilesExt              bool                   `json:"incomplete_files_ext"`
	IpFilterEnabled                 bool                   `json:"ip_filter_enabled"`
	IpFilterPath                    string                 `json:"ip_filter_path"`
	IpFilterTrackers                bool                   `json:"ip_filter_trackers"`
	LimitLanPeers                   bool                   `json:"limit_lan_peers"`
	LimitTcpOverhead                bool                   `json:"limit_tcp_overhead"`
	LimitUtpRate                    bool                   `json:"limit_utp_rate"`
	ListenPort                      int                    `json:"listen_port"`
	Locale                          string                 `json:"locale"`
	Lsd                             bool                   `json:"lsd"`
	MailNotificationAuthEnabled     bool                   `json:"mail_notification_auth_enabled"`
	MailNotificationEmail           string                 `json:"mail_notification_email"`
	MailNotificationEnabled         bool                   `json:"mail_notification_enabled"`
	MailNotificationPassword        string                 `json:"mail_notification_password"`
	MailNotificationSender          string                 `json:"mail_notification_sender"`
	MailNotificationSmtp            string                 `json:"mail_notification_smtp"`
	MailNotificationSslEnabled      bool                   `json:"mail_notification_ssl_enabled"`
	MailNotificationUsername        string                 `json:"mail_notification_username"`
	MarkOfTheWeb                    bool                   `json:"mark_of_the_web"`
	MaxActiveCheckingTorrents       int                    `json:"max_active_checking_torrents"`
	MaxActiveDownloads              int                    `json:"max_active_downloads"`
	MaxActiveTorrents               int                    `json:"max_active_torrents"`
	MaxActiveUploads                int                    `json:"max_active_uploads"`
	MaxConcurrentHttpAnnounces      int                    `json:"max_concurrent_http_announces"`
	MaxConnec                       int                    `json:"max_connec"`
	MaxConnecPerTorrent             int                    `json:"max_connec_per_torrent"`
	MaxInactiveSeedingTime          int                    `json:"max_inactive_seeding_time"`
	MaxInactiveSeedingTimeEnabled   bool                   `json:"max_inactive_seeding_time_enabled"`
	MaxRatio                        float64                `json:"max_ratio"`
	MaxRatioAct                     int                    `json:"max_ratio_act"`
	MaxRatioEnabled                 bool                   `json:"max_ratio_enabled"`
	MaxSeedingTime                  int                    `json:"max_seeding_time"`
	MaxSeedingTimeEnabled           bool                   `json:"max_seeding_time_enabled"`
	MaxUploads                      int                    `json:"max_uploads"`
	MaxUploadsPerTorrent            int                    `json:"max_uploads_per_torrent"`
	MemoryWorkingSetLimit           int                    `json:"memory_working_set_limit"`
	MergeTrackers                   bool                   `json:"merge_trackers"`
	OutgoingPortsMax                int                    `json:"outgoing_ports_max"`
	OutgoingPortsMin                int                    `json:"outgoing_ports_min"`
	PeerTos                         int                    `json:"peer_tos"`
	PeerTurnover                    int                    `json:"peer_turnover"`
	PeerTurnoverCutoff              int                    `json:"peer_turnover_cutoff"`
	PeerTurnoverInterval            int                    `json:"peer_turnover_interval"`
	PerformanceWarning              bool                   `json:"performance_warning"`
	Pex                             bool                   `json:"pex"`
	PreallocateAll                  bool                   `json:"preallocate_all"`
	ProxyAuthEnabled                bool                   `json:"proxy_auth_enabled"`
	ProxyBittorrent                 bool                   `json:"proxy_bittorrent"`
	ProxyHostnameLookup             bool                   `json:"proxy_hostname_lookup"`
	ProxyIp                         string                 `json:"proxy_ip"`
	ProxyMisc                       bool                   `json:"proxy_misc"`
	ProxyPassword                   string                 `json:"proxy_password"`
	ProxyPeerConnections            bool                   `json:"proxy_peer_connections"`
	ProxyPort                       int                    `json:"proxy_port"`
	ProxyRss                        bool                   `json:"proxy_rss"`
	ProxyType                       string                 `json:"proxy_type"`
	ProxyUsername                   string                 `json:"proxy_username"`
	PythonExecutablePath            string                 `json:"python_executable_path"`
	QueueingEnabled                 bool                   `json:"queueing_enabled"`
	RandomPort                      bool                   `json:"random_port"`
	ReannounceWhenAddressChanged    bool                   `json:"reannounce_when_address_changed"`
	RecheckCompletedTorrents        bool                   `json:"recheck_completed_torrents"`
	RefreshInterval                 int                    `json:"refresh_interval"`
	RequestQueueSize                int                    `json:"request_queue_size"`
	ResolvePeerCountries            bool                   `json:"resolve_peer_countries"`
	ResolvePeerHostNames            bool                   `json:"resolve_peer_host_names"`
	ResumeDataStorageType           string                 `json:"resume_data_storage_type"`
	RssAutoDownloadingEnabled       bool                   `json:"rss_auto_downloading_enabled"`
	RssDownloadRepackProperEpisodes bool                   `json:"rss_download_repack_proper_episodes"`
	RssFetchDelay                   int64                  `json:"rss_fetch_delay"`
	RssMaxArticlesPerFeed           int                    `json:"rss_max_articles_per_feed"`
	RssProcessingEnabled            bool                   `json:"rss_processing_enabled"`
	RssRefreshInterval              int                    `json:"rss_refresh_interval"`
	RssSmartEpisodeFilters          string                 `json:"rss_smart_episode_filters"`
	SavePath                        string                 `json:"save_path"`
	SavePathChangedTmmEnabled       bool                   `json:"save_path_changed_tmm_enabled"`
	SaveResumeDataInterval          int                    `json:"save_resume_data_interval"`
	SaveStatisticsInterval          int                    `json:"save_statistics_interval"`
	ScanDirs                        map[string]interface{} `json:"scan_dirs"`
	ScheduleFromHour                int                    `json:"schedule_from_hour"`
	ScheduleFromMin                 int                    `json:"schedule_from_min"`
	ScheduleToHour                  int                    `json:"schedule_to_hour"`
	ScheduleToMin                   int                    `json:"schedule_to_min"`
	SchedulerDays                   int                    `json:"scheduler_days"`
	SchedulerEnabled                bool                   `json:"scheduler_enabled"`
	SendBufferLowWatermark          int                    `json:"send_buffer_low_watermark"`
	SendBufferWatermark             int                    `json:"send_buffer_watermark"`
	SendBufferWatermarkFactor       int                    `json:"send_buffer_watermark_factor"`
	ShareLimitsMode                 string                 `json:"share_limits_mode"`
	SlowTorrentDlRateThreshold      int                    `json:"slow_torrent_dl_rate_threshold"`
	SlowTorrentInactiveTimer        int                    `json:"slow_torrent_inactive_timer"`
	SlowTorrentUlRateThreshold      int                    `json:"slow_torrent_ul_rate_threshold"`
	SocketBacklogSize               int                    `json:"socket_backlog_size"`
	SocketReceiveBufferSize         int                    `json:"socket_receive_buffer_size"`
	SocketSendBufferSize            int                    `json:"socket_send_buffer_size"`
	SsrfMitigation                  bool                   `json:"ssrf_mitigation"`
	SslEnabled                      bool                   `json:"ssl_enabled"`
	SslListenPort                   int                    `json:"ssl_listen_port"`
	StatusBarExternalIP             bool                   `json:"status_bar_external_ip"`
	StopTrackerTimeout              int                    `json:"stop_tracker_timeout"`
	TempPath                        string                 `json:"temp_path"`
	TempPathEnabled                 bool                   `json:"temp_path_enabled"`
	TorrentChangedTmmEnabled        bool                   `json:"torrent_changed_tmm_enabled"`
	TorrentContentLayout            string                 `json:"torrent_content_layout"`
	TorrentContentRemoveOption      string                 `json:"torrent_content_remove_option"`
	TorrentFileSizeLimit            int                    `json:"torrent_file_size_limit"`
	TorrentStopCondition            string                 `json:"torrent_stop_condition"`
	UpLimit                         int                    `json:"up_limit"`
	UploadChokingAlgorithm          int                    `json:"upload_choking_algorithm"`
	UploadSlotsBehavior             int                    `json:"upload_slots_behavior"`
	Upnp                            bool                   `json:"upnp"`
	UpnpLeaseDuration               int                    `json:"upnp_lease_duration"`
	UseCategoryPathsInManualMode    bool                   `json:"use_category_paths_in_manual_mode"`
	UseHttps                        bool                   `json:"use_https"`
	UseUnwantedFolder               bool                   `json:"use_unwanted_folder"`
	UtpTcpMixedMode                 int                    `json:"utp_tcp_mixed_mode"`
	ValidateHttpsTrackerCertificate bool                   `json:"validate_https_tracker_certificate"`
	WebUiAddress                    string                 `json:"web_ui_address"`
	WebUiAPIKey                     string                 `json:"web_ui_api_key"`
	WebUiBanDuration                int                    `json:"web_ui_ban_duration"`
	WebUiClickjackingProtectionEnabled bool                `json:"web_ui_clickjacking_protection_enabled"`
	WebUiCsrfProtectionEnabled      bool                   `json:"web_ui_csrf_protection_enabled"`
	WebUiCustomHttpHeaders          string                 `json:"web_ui_custom_http_headers"`
	WebUiDomainList                 string                 `json:"web_ui_domain_list"`
	WebUiHostHeaderValidationEnabled bool                  `json:"web_ui_host_header_validation_enabled"`
	WebUiHttpsCertPath              string                 `json:"web_ui_https_cert_path"`
	WebUiHttpsKeyPath               string                 `json:"web_ui_https_key_path"`
	WebUiMaxAuthFailCount           int                    `json:"web_ui_max_auth_fail_count"`
	WebUiPort                       int                    `json:"web_ui_port"`
	WebUiReverseProxiesList         string                 `json:"web_ui_reverse_proxies_list"`
	WebUiReverseProxyEnabled        bool                   `json:"web_ui_reverse_proxy_enabled"`
	WebUiSecureCookieEnabled        bool                   `json:"web_ui_secure_cookie_enabled"`
	WebUiSessionTimeout             int                    `json:"web_ui_session_timeout"`
	WebUiUpnp                       bool                   `json:"web_ui_upnp"`
	WebUiUseCustomHttpHeadersEnabled bool                  `json:"web_ui_use_custom_http_headers_enabled"`
	WebUiUsername                   string                 `json:"web_ui_username"`
}

// Log is one row from api/v2/log/main (timestamp is ms since epoch).
type Log struct {
	ID        int    `json:"id"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
	Type      int    `json:"type"`
}

// PeerLog is one row from api/v2/log/peers.
type PeerLog struct {
	ID        int    `json:"id"`
	IP        string `json:"ip"`
	Blocked   bool   `json:"blocked"`
	Timestamp int64  `json:"timestamp"`
	Reason    string `json:"reason"`
}

// Info is api/v2/transfer/info (TransferController::infoAction only).
type Info struct {
	ConnectionStatus      string `json:"connection_status"`
	DhtNodes              int64  `json:"dht_nodes"`
	DlInfoData            int64  `json:"dl_info_data"`
	DlInfoSpeed           int64  `json:"dl_info_speed"`
	DlRateLimit           int64  `json:"dl_rate_limit"`
	UpInfoData            int64  `json:"up_info_data"`
	UpInfoSpeed           int64  `json:"up_info_speed"`
	UpRateLimit           int64  `json:"up_rate_limit"`
	LastExternalAddressV4 string `json:"last_external_address_v4"`
	LastExternalAddressV6 string `json:"last_external_address_v6"`
}

type TorrentsOptions struct {
	Filter   *string  // all, downloading, completed, paused, active, inactive => optional
	Category *string  // => optional
	Sort     *string  // => optional
	Reverse  *bool    // => optional
	Limit    *int     // => optional (no negatives)
	Offset   *int     // => optional (negatives allowed)
	Hashes   []string // separated by | => optional
}

// Category of torrent
type Category struct {
	Name     string `json:"name"`
	SavePath string `json:"savePath"`
}

// Categories is the response from api/v2/torrents/categories (map category name -> options).
type Categories map[string]Category

// LoginOptions contains all options for /login endpoint
type LoginOptions struct {
	Username string
	Password string
}

// AddTrackersOptions contains all options for /addTrackers endpoint
type AddTrackersOptions struct {
	Hash     string
	Trackers []string
}

// EditTrackerOptions contains all options for /editTracker endpoint
type EditTrackerOptions struct {
	Hash    string
	OrigURL string
	NewURL  string
}

// RemoveTrackersOptions contains all options for /removeTrackers endpoint
type RemoveTrackersOptions struct {
	Hash     string
	Trackers []string
}

type DownloadOptions struct {
	Savepath                   *string
	Cookie                     *string
	Category                   *string
	SkipHashChecking           *bool
	Paused                     *bool
	RootFolder                 *bool
	Rename                     *string
	UploadSpeedLimit           *int
	DownloadSpeedLimit         *int
	SequentialDownload         *bool
	AutomaticTorrentManagement *bool
	FirstLastPiecePriority     *bool
}

type InfoOptions struct {
	Filter   *string
	Category *string
	Sort     *string
	Reverse  *bool
	Limit    *int
	Offset   *int
	Hashes   []string
}

type PriorityValues int

const (
	Do_not_download  PriorityValues = 0
	Normal_priority  PriorityValues = 1
	High_priority    PriorityValues = 6
	Maximal_priority PriorityValues = 7
)

// ProcessInfo is returned by api/v2/app/processInfo.
type ProcessInfo struct {
	LaunchTime int64 `json:"launch_time"`
}

// NetworkInterface is an entry from api/v2/app/networkInterfaceList.
type NetworkInterface struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AppCookie is one cookie from api/v2/app/cookies.
type AppCookie struct {
	Name           string `json:"name"`
	Domain         string `json:"domain"`
	Path           string `json:"path"`
	Value          string `json:"value"`
	ExpirationDate int64  `json:"expirationDate"`
}

// DirectoryContentMode filters entries from api/v2/app/getDirectoryContent (param mode).
type DirectoryContentMode string

const (
	DirectoryContentAll   DirectoryContentMode = "all"
	DirectoryContentDirs  DirectoryContentMode = "dirs"
	DirectoryContentFiles DirectoryContentMode = "files"
)

// DirectoryContentFileMetadata is one element when withMetadata=true on getDirectoryContent.
type DirectoryContentFileMetadata struct {
	Name                 string `json:"name"`
	Type                 string `json:"type"` // "dir" or "file"
	Size                 int64  `json:"size,omitempty"`
	CreationDate         int64  `json:"creation_date"`
	LastAccessDate       int64  `json:"last_access_date"`
	LastModificationDate int64  `json:"last_modification_date"`
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
