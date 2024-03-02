package qbt

/**
API v2.9.3 (qBittorrent 4.6.2)
https://github.com/qbittorrent/qBittorrent/wiki/WebUI-API-(qBittorrent-4.1)#api-v283
*/

// Torrent api/v2/torrents/properties
type Torrent struct {
	SavePath           string  `json:"save_path"`
	CreationDate       int64   `json:"creation_date"`
	PieceSize          int64   `json:"piece_size"`
	Comment            string  `json:"comment"`
	TotalWasted        int64   `json:"total_wasted"`
	TotalUl            int64   `json:"total_uploaded"`
	TotalUlSession     int64   `json:"total_uploaded_session"`
	TotalDl            int64   `json:"total_downloaded"`
	TotalDlSession     int64   `json:"total_downloaded_session"`
	UpLimit            int64   `json:"up_limit"`
	DlLimit            int64   `json:"dl_limit"`
	TimeElapsed        int64   `json:"time_elapsed"`
	SeedingTime        int64   `json:"seeding_time"`
	NbConnections      int     `json:"nb_connections"`
	NbConnectionsLimit int     `json:"nb_connections_limit"`
	ShareRatio         float64 `json:"share_ratio"`
	AdditionDate       int64   `json:"addition_date"`
	CompletionDate     int64   `json:"completion_date"`
	CreatedBy          string  `json:"created_by"`
	DlSpeedAvg         int64   `json:"dl_speed_avg"`
	DlSpeed            int64   `json:"dl_speed"`
	Eta                int64   `json:"eta"`
	LastSeen           int64   `json:"last_seen"`
	Peers              int     `json:"peers"`
	PeersTotal         int     `json:"peers_total"`
	PiecesHave         int     `json:"pieces_have"`
	PiecesNum          int     `json:"pieces_num"`
	Reannounce         int     `json:"reannounce"`
	Seeds              int     `json:"seeds"`
	SeedsTotal         int     `json:"seeds_total"`
	TotalSize          int     `json:"total_size"`
	UpSpeedAvg         int64   `json:"up_speed_avg"`
	UpSpeed            int64   `json:"up_speed"`
}

// TorrentInfo api/v2/torrents/info
type TorrentInfo struct {
	AddedOn           int64   `json:"added_on"`
	AmountLeft        int64   `json:"amount_left"`
	AutoTmm           bool    `json:"auto_tmm"`
	Availability      float64 `json:"availability"`
	Category          string  `json:"category"`
	Completed         int64   `json:"completed"`
	CompletionOn      int64   `json:"completion_on"`
	ContentPath       string  `json:"content_path"`
	DlLimit           int64   `json:"dl_limit"`
	Dlspeed           int64   `json:"dlspeed"`
	Downloaded        int64   `json:"downloaded"`
	DownloadedSession int64   `json:"downloaded_session"`
	Eta               int64   `json:"eta"`
	FLPiecePrio       bool    `json:"f_l_piece_prio"`
	ForceStart        bool    `json:"force_start"`
	Hash              string  `json:"hash"`
	LastActivity      int64   `json:"last_activity"`
	MagnetURI         string  `json:"magnet_uri"`
	MaxRatio          float64 `json:"max_ratio"`
	MaxSeedingTime    int64   `json:"max_seeding_time"`
	Name              string  `json:"name"`
	NumComplete       int64   `json:"num_complete"`
	NumIncomplete     int64   `json:"num_incomplete"`
	NumLeechs         int64   `json:"num_leechs"`
	NumSeeds          int64   `json:"num_seeds"`
	Priority          int64   `json:"priority"`
	Progress          float64 `json:"progress"`
	Ratio             float64 `json:"ratio"`
	RatioLimit        float64 `json:"ratio_limit"`
	SavePath          string  `json:"save_path"`
	SeedingTime       int64   `json:"seeding_time"`
	SeedingTimeLimit  int64   `json:"seeding_time_limit"`
	SeenComplete      int64   `json:"seen_complete"`
	SeqDl             bool    `json:"seq_dl"`
	Size              int64   `json:"size"`
	State             string  `json:"state"`
	SuperSeeding      bool    `json:"super_seeding"`
	Tags              string  `json:"tags"`
	TimeActive        int64   `json:"time_active"`
	TotalSize         int64   `json:"total_size"`
	Tracker           string  `json:"tracker"`
	TrackersCount     int64   `json:"trackers_count"` // not provided in the API docs!!!
	UpLimit           int64   `json:"up_limit"`
	Uploaded          int64   `json:"uploaded"`
	UploadedSession   int64   `json:"uploaded_session"`
	Upspeed           int64   `json:"upspeed"`
}

// Tracker holds a tracker object from qbittorrent
type Tracker struct {
	URL           string `json:"url"`
	Status        uint8  `json:"status"`
	Tier          int    `json:"tier"`
	NumPeers      int    `json:"num_peers"`
	NumSeeds      int    `json:"num_seeds"`
	NumLeeches    int    `json:"num_leeches"`
	NumDownloaded int    `json:"num_downloaded"`
	Msg           string `json:"msg"`
}

// WebSeed holds a webseed object from qbittorrent
type WebSeed struct {
	URL string `json:"url"`
}

// TorrentFile holds a torrent file object from qbittorrent
type TorrentFile struct {
	Index        int     `json:"index"`
	Name         string  `json:"name"`
	Size         int64   `json:"size"`
	Progress     float64 `json:"progress"`
	Priority     int8    `json:"priority"`
	IsSeed       bool    `json:"is_seed"`
	PieceRange   []uint  `json:"piece_range"`
	Availability float32 `json:"availability"`
}

// Sync holds the sync response struct which contains full info for GUI
// Used by the official WebUI
type Sync struct {
	Rid             uint64                 `json:"rid"`
	FullUpdate      bool                   `json:"full_update"`
	Torrents        map[string]TorrentInfo `json:"torrents"`
	TorrentsRemoved []string               `json:"torrents_removed"`
	Categories      []struct {
		Name     string `json:"name"`
		SavePath string `json:"savePath"`
	} `json:"categories"`
	CategoriesRemoved []string            `json:"categories_removed"`
	Tags              []string            `json:"tags"`
	TagsRemoved       []string            `json:"tags_removed"`
	ServerState       []ServerState       `json:"server_state"`
	Trackers          map[string][]string `json:"trackers"` // not provided in the API docs!!!
}
type ServerState struct {
	AllTimeDL            int64  `json:"alltime_dl"`
	AllTimeUL            int64  `json:"alltime_ul"`
	AverageTimeQueue     int    `json:"average_time_queue"`
	ConnectionStatus     string `json:"connection_status"`
	DhtNodes             int    `json:"dht_nodes"`
	DlInfoData           int    `json:"dl_info_data"`
	DlInfoSpeed          int    `json:"dl_info_speed"`
	DlRateLimit          int    `json:"dl_rate_limit"`
	FreeSpaceOnDisk      int64  `json:"free_space_on_disk"`
	GlobalRatio          string `json:"global_ratio"` // WTF, why not float?
	QueuedIoJobs         int    `json:"queued_io_jobs"`
	Queueing             bool   `json:"queueing"`
	ReadCacheHits        string `json:"read_cache_hits"`     // ! float as string
	ReadCacheOverload    string `json:"read_cache_overload"` // ! float
	RefreshInterval      int    `json:"refresh_interval"`
	TotalBuffersSize     int64  `json:"total_buffers_size"`
	TotalPeerConnections int    `json:"total_peer_connections"`
	TotalQueuedSize      int    `json:"total_queued_size"`
	TotalWastedSession   int    `json:"total_wasted_session"`
	UpInfoData           int64  `json:"up_info_data"`
	UpInfoSpeed          int64  `json:"up_info_speed"`
	UpRateLimit          int64  `json:"up_rate_limit"`
	UseAltSpeedLimits    bool   `json:"use_alt_speed_limits"`
	UseSubcategories     bool   `json:"use_subcategories"`
	WriteCacheOverload   string `json:"write_cache_overload"` // ! float

}

type TorrentPeers struct {
	FullUpdate bool            `json:"full_update"`
	Peers      map[string]Peer `json:"peers"`
	Rid        uint64          `json:"rid"`
	ShowFlags  bool            `json:"show_flags"`
}

type Peer struct {
	Client       string  `json:"client"`
	Connection   string  `json:"connection"`
	Country      string  `json:"country"`
	CountryCode  string  `json:"country_code"`
	DlSpeed      int     `json:"dl_speed"`
	Downloaded   int     `json:"downloaded"`
	Files        string  `json:"files"`
	Flags        string  `json:"flags"`
	FlagsDesc    string  `json:"flags_desc"`
	Ip           string  `json:"ip"`
	PeerIdClient string  `json:"peer_id_client"`
	Port         int     `json:"port"`
	Progress     float64 `json:"progress"`
	Relevance    int     `json:"relevance"`
	UpSpeed      int     `json:"up_speed"`
	Uploaded     int64   `json:"uploaded"`
}

type BuildInfo struct {
	QTVersion         string `json:"qt"`
	LibtorrentVersion string `json:"libtorrent"`
	BoostVersion      string `json:"boost"`
	OpenSSLVersion    string `json:"openssl"`
	AppBitness        uint8  `json:"bitness"`
	ZLib              string `json:"zlib"`
}

type Preferences struct {
	AddToTopOfQueue                    bool              `json:"add_to_top_of_queue"`
	AddTrackers                        string            `json:"add_trackers"`
	AddTrackersEnabled                 bool              `json:"add_trackers_enabled"`
	AltDlLimit                         int               `json:"alt_dl_limit"`
	AltUpLimit                         int               `json:"alt_up_limit"`
	AlternativeWebuiEnabled            bool              `json:"alternative_webui_enabled"`
	AlternativeWebuiPath               string            `json:"alternative_webui_path"`
	AnnounceIp                         string            `json:"announce_ip"`
	AnnounceToAllTiers                 bool              `json:"announce_to_all_tiers"`
	AnnounceToAllTrackers              bool              `json:"announce_to_all_trackers"`
	AnonymousMode                      bool              `json:"anonymous_mode"`
	AsyncIoThreads                     int               `json:"async_io_threads"`
	AutoBanBtPlayerPeer                bool              `json:"auto_ban_bt_player_peer"`
	AutoBanUnknownPeer                 bool              `json:"auto_ban_unknown_peer"`
	AutoDeleteMode                     int               `json:"auto_delete_mode"`
	AutoTmmEnabled                     bool              `json:"auto_tmm_enabled"`
	AutoUpdateTrackersEnabled          bool              `json:"auto_update_trackers_enabled"`
	AutorunEnabled                     bool              `json:"autorun_enabled"`
	AutorunOnTorrentAddedEnabled       bool              `json:"autorun_on_torrent_added_enabled"`
	AutorunOnTorrentAddedProgram       string            `json:"autorun_on_torrent_added_program"`
	AutorunProgram                     string            `json:"autorun_program"`
	BannedIPs                          string            `json:"banned_IPs"`
	BdecodeDepthLimit                  int               `json:"bdecode_depth_limit"`
	BdecodeTokenLimit                  int               `json:"bdecode_token_limit"`
	BittorrentProtocol                 int               `json:"bittorrent_protocol"`
	BlockPeersOnPrivilegedPorts        bool              `json:"block_peers_on_privileged_ports"`
	BypassAuthSubnetWhitelist          string            `json:"bypass_auth_subnet_whitelist"`
	BypassAuthSubnetWhitelistEnabled   bool              `json:"bypass_auth_subnet_whitelist_enabled"`
	BypassLocalAuth                    bool              `json:"bypass_local_auth"`
	CategoryChangedTmmEnabled          bool              `json:"category_changed_tmm_enabled"`
	CheckingMemoryUse                  int               `json:"checking_memory_use"`
	ConnectionSpeed                    int               `json:"connection_speed"`
	CurrentInterfaceAddress            string            `json:"current_interface_address"`
	CurrentInterfaceName               string            `json:"current_interface_name"`
	CurrentNetworkInterface            string            `json:"current_network_interface"`
	CustomizeTrackersListUrl           string            `json:"customize_trackers_list_url"`
	Dht                                bool              `json:"dht"`
	DiskCache                          int               `json:"disk_cache"`
	DiskCacheTtl                       int               `json:"disk_cache_ttl"`
	DiskIoReadMode                     int               `json:"disk_io_read_mode"`
	DiskIoType                         int               `json:"disk_io_type"`
	DiskIoWriteMode                    int               `json:"disk_io_write_mode"`
	DiskQueueSize                      int               `json:"disk_queue_size"`
	DlLimit                            int               `json:"dl_limit"`
	DontCountSlowTorrents              bool              `json:"dont_count_slow_torrents"`
	DyndnsDomain                       string            `json:"dyndns_domain"`
	DyndnsEnabled                      bool              `json:"dyndns_enabled"`
	DyndnsPassword                     string            `json:"dyndns_password"`
	DyndnsService                      int               `json:"dyndns_service"`
	DyndnsUsername                     string            `json:"dyndns_username"`
	EmbeddedTrackerPort                int               `json:"embedded_tracker_port"`
	EmbeddedTrackerPortForwarding      bool              `json:"embedded_tracker_port_forwarding"`
	EnableCoalesceReadWrite            bool              `json:"enable_coalesce_read_write"`
	EnableEmbeddedTracker              bool              `json:"enable_embedded_tracker"`
	EnableMultiConnectionsFromSameIp   bool              `json:"enable_multi_connections_from_same_ip"`
	EnablePieceExtentAffinity          bool              `json:"enable_piece_extent_affinity"`
	EnableUploadSuggestions            bool              `json:"enable_upload_suggestions"`
	Encryption                         int               `json:"encryption"`
	ExcludedFileNames                  string            `json:"excluded_file_names"`
	ExcludedFileNamesEnabled           bool              `json:"excluded_file_names_enabled"`
	ExportDir                          string            `json:"export_dir"`
	ExportDirFin                       string            `json:"export_dir_fin"`
	FileLogAge                         int               `json:"file_log_age"`
	FileLogAgeType                     int               `json:"file_log_age_type"`
	FileLogBackupEnabled               bool              `json:"file_log_backup_enabled"`
	FileLogDeleteOld                   bool              `json:"file_log_delete_old"`
	FileLogEnabled                     bool              `json:"file_log_enabled"`
	FileLogMaxSize                     int               `json:"file_log_max_size"`
	FileLogPath                        string            `json:"file_log_path"`
	FilePoolSize                       int               `json:"file_pool_size"`
	HashingThreads                     int               `json:"hashing_threads"`
	I2PAddress                         string            `json:"i2p_address"`
	I2PEnabled                         bool              `json:"i2p_enabled"`
	I2PInboundLength                   int               `json:"i2p_inbound_length"`
	I2PInboundQuantity                 int               `json:"i2p_inbound_quantity"`
	I2PMixedMode                       bool              `json:"i2p_mixed_mode"`
	I2POutboundLength                  int               `json:"i2p_outbound_length"`
	I2POutboundQuantity                int               `json:"i2p_outbound_quantity"`
	I2PPort                            int               `json:"i2p_port"`
	IdnSupportEnabled                  bool              `json:"idn_support_enabled"`
	IncompleteFilesExt                 bool              `json:"incomplete_files_ext"`
	IpFilterEnabled                    bool              `json:"ip_filter_enabled"`
	IpFilterPath                       string            `json:"ip_filter_path"`
	IpFilterTrackers                   bool              `json:"ip_filter_trackers"`
	LimitLanPeers                      bool              `json:"limit_lan_peers"`
	LimitTcpOverhead                   bool              `json:"limit_tcp_overhead"`
	LimitUtpRate                       bool              `json:"limit_utp_rate"`
	ListenPort                         int               `json:"listen_port"`
	Locale                             string            `json:"locale"`
	Lsd                                bool              `json:"lsd"`
	MailNotificationAuthEnabled        bool              `json:"mail_notification_auth_enabled"`
	MailNotificationEmail              string            `json:"mail_notification_email"`
	MailNotificationEnabled            bool              `json:"mail_notification_enabled"`
	MailNotificationPassword           string            `json:"mail_notification_password"`
	MailNotificationSender             string            `json:"mail_notification_sender"`
	MailNotificationSmtp               string            `json:"mail_notification_smtp"`
	MailNotificationSslEnabled         bool              `json:"mail_notification_ssl_enabled"`
	MailNotificationUsername           string            `json:"mail_notification_username"`
	MaxActiveCheckingTorrents          int               `json:"max_active_checking_torrents"`
	MaxActiveDownloads                 int               `json:"max_active_downloads"`
	MaxActiveTorrents                  int               `json:"max_active_torrents"`
	MaxActiveUploads                   int               `json:"max_active_uploads"`
	MaxConcurrentHttpAnnounces         int               `json:"max_concurrent_http_announces"`
	MaxConnec                          int               `json:"max_connec"`
	MaxConnecPerTorrent                int               `json:"max_connec_per_torrent"`
	MaxInactiveSeedingTime             int               `json:"max_inactive_seeding_time"`
	MaxInactiveSeedingTimeEnabled      bool              `json:"max_inactive_seeding_time_enabled"`
	MaxRatio                           int               `json:"max_ratio"`
	MaxRatioAct                        int               `json:"max_ratio_act"`
	MaxRatioEnabled                    bool              `json:"max_ratio_enabled"`
	MaxSeedingTime                     int               `json:"max_seeding_time"`
	MaxSeedingTimeEnabled              bool              `json:"max_seeding_time_enabled"`
	MaxUploads                         int               `json:"max_uploads"`
	MaxUploadsPerTorrent               int               `json:"max_uploads_per_torrent"`
	MemoryWorkingSetLimit              int               `json:"memory_working_set_limit"`
	MergeTrackers                      bool              `json:"merge_trackers"`
	OutgoingPortsMax                   int               `json:"outgoing_ports_max"`
	OutgoingPortsMin                   int               `json:"outgoing_ports_min"`
	PeerTos                            int               `json:"peer_tos"`
	PeerTurnover                       int               `json:"peer_turnover"`
	PeerTurnoverCutoff                 int               `json:"peer_turnover_cutoff"`
	PeerTurnoverInterval               int               `json:"peer_turnover_interval"`
	PerformanceWarning                 bool              `json:"performance_warning"`
	Pex                                bool              `json:"pex"`
	PreallocateAll                     bool              `json:"preallocate_all"`
	ProxyAuthEnabled                   bool              `json:"proxy_auth_enabled"`
	ProxyBittorrent                    bool              `json:"proxy_bittorrent"`
	ProxyHostnameLookup                bool              `json:"proxy_hostname_lookup"`
	ProxyIp                            string            `json:"proxy_ip"`
	ProxyMisc                          bool              `json:"proxy_misc"`
	ProxyPassword                      string            `json:"proxy_password"`
	ProxyPeerConnections               bool              `json:"proxy_peer_connections"`
	ProxyPort                          int               `json:"proxy_port"`
	ProxyRss                           bool              `json:"proxy_rss"`
	ProxyType                          string            `json:"proxy_type"`
	ProxyUsername                      string            `json:"proxy_username"`
	PublicTrackers                     string            `json:"public_trackers"`
	QueueingEnabled                    bool              `json:"queueing_enabled"`
	RandomPort                         bool              `json:"random_port"`
	ReannounceWhenAddressChanged       bool              `json:"reannounce_when_address_changed"`
	RecheckCompletedTorrents           bool              `json:"recheck_completed_torrents"`
	RefreshInterval                    int               `json:"refresh_interval"`
	RequestQueueSize                   int               `json:"request_queue_size"`
	ResolvePeerCountries               bool              `json:"resolve_peer_countries"`
	ResumeDataStorageType              string            `json:"resume_data_storage_type"`
	RssAutoDownloadingEnabled          bool              `json:"rss_auto_downloading_enabled"`
	RssDownloadRepackProperEpisodes    bool              `json:"rss_download_repack_proper_episodes"`
	RssMaxArticlesPerFeed              int               `json:"rss_max_articles_per_feed"`
	RssProcessingEnabled               bool              `json:"rss_processing_enabled"`
	RssRefreshInterval                 int               `json:"rss_refresh_interval"`
	RssSmartEpisodeFilters             string            `json:"rss_smart_episode_filters"`
	SavePath                           string            `json:"save_path"`
	SavePathChangedTmmEnabled          bool              `json:"save_path_changed_tmm_enabled"`
	SaveResumeDataInterval             int               `json:"save_resume_data_interval"`
	ScanDirs                           map[string]string `json:"scan_dirs"`
	ScheduleFromHour                   int               `json:"schedule_from_hour"`
	ScheduleFromMin                    int               `json:"schedule_from_min"`
	ScheduleToHour                     int               `json:"schedule_to_hour"`
	ScheduleToMin                      int               `json:"schedule_to_min"`
	SchedulerDays                      int               `json:"scheduler_days"`
	SchedulerEnabled                   bool              `json:"scheduler_enabled"`
	SendBufferLowWatermark             int               `json:"send_buffer_low_watermark"`
	SendBufferWatermark                int               `json:"send_buffer_watermark"`
	SendBufferWatermarkFactor          int               `json:"send_buffer_watermark_factor"`
	SlowTorrentDlRateThreshold         int               `json:"slow_torrent_dl_rate_threshold"`
	SlowTorrentInactiveTimer           int               `json:"slow_torrent_inactive_timer"`
	SlowTorrentUlRateThreshold         int               `json:"slow_torrent_ul_rate_threshold"`
	SocketBacklogSize                  int               `json:"socket_backlog_size"`
	SocketReceiveBufferSize            int               `json:"socket_receive_buffer_size"`
	SocketSendBufferSize               int               `json:"socket_send_buffer_size"`
	SsrfMitigation                     bool              `json:"ssrf_mitigation"`
	StartPausedEnabled                 bool              `json:"start_paused_enabled"`
	StopTrackerTimeout                 int               `json:"stop_tracker_timeout"`
	TempPath                           string            `json:"temp_path"`
	TempPathEnabled                    bool              `json:"temp_path_enabled"`
	TorrentChangedTmmEnabled           bool              `json:"torrent_changed_tmm_enabled"`
	TorrentContentLayout               string            `json:"torrent_content_layout"`
	TorrentFileSizeLimit               int               `json:"torrent_file_size_limit"`
	TorrentStopCondition               string            `json:"torrent_stop_condition"`
	UpLimit                            int               `json:"up_limit"`
	UploadChokingAlgorithm             int               `json:"upload_choking_algorithm"`
	UploadSlotsBehavior                int               `json:"upload_slots_behavior"`
	Upnp                               bool              `json:"upnp"`
	UpnpLeaseDuration                  int               `json:"upnp_lease_duration"`
	UseCategoryPathsInManualMode       bool              `json:"use_category_paths_in_manual_mode"`
	UseHttps                           bool              `json:"use_https"`
	UseSubcategories                   bool              `json:"use_subcategories"`
	UtpTcpMixedMode                    int               `json:"utp_tcp_mixed_mode"`
	ValidateHttpsTrackerCertificate    bool              `json:"validate_https_tracker_certificate"`
	WebUiAddress                       string            `json:"web_ui_address"`
	WebUiBanDuration                   int               `json:"web_ui_ban_duration"`
	WebUiClickjackingProtectionEnabled bool              `json:"web_ui_clickjacking_protection_enabled"`
	WebUiCsrfProtectionEnabled         bool              `json:"web_ui_csrf_protection_enabled"`
	WebUiCustomHttpHeaders             string            `json:"web_ui_custom_http_headers"`
	WebUiDomainList                    string            `json:"web_ui_domain_list"`
	WebUiHostHeaderValidationEnabled   bool              `json:"web_ui_host_header_validation_enabled"`
	WebUiHttpsCertPath                 string            `json:"web_ui_https_cert_path"`
	WebUiHttpsKeyPath                  string            `json:"web_ui_https_key_path"`
	WebUiMaxAuthFailCount              int               `json:"web_ui_max_auth_fail_count"`
	WebUiPort                          int               `json:"web_ui_port"`
	WebUiReverseProxiesList            string            `json:"web_ui_reverse_proxies_list"`
	WebUiReverseProxyEnabled           bool              `json:"web_ui_reverse_proxy_enabled"`
	WebUiSecureCookieEnabled           bool              `json:"web_ui_secure_cookie_enabled"`
	WebUiSessionTimeout                int               `json:"web_ui_session_timeout"`
	WebUiUpnp                          bool              `json:"web_ui_upnp"`
	WebUiUseCustomHttpHeadersEnabled   bool              `json:"web_ui_use_custom_http_headers_enabled"`
	WebUiUsername                      string            `json:"web_ui_username"`
}

// Log
type Log struct {
	ID        int    `json:"id"`
	Message   string `json:"message"`
	Timestamp int    `json:"timestamp"`
	Type      int    `json:"type"`
}

// PeerLog
type PeerLog struct {
	ID        int    `json:"id"`
	IP        string `json:"ip"`
	Blocked   bool   `json:"blocked"`
	Timestamp int    `json:"timestamp"`
	Reason    string `json:"reason"`
}

// Info
type Info struct {
	ConnectionStatus  string `json:"connection_status"`
	DHTNodes          int    `json:"dht_nodes"`
	DlInfoData        int    `json:"dl_info_data"`
	DlInfoSpeed       int    `json:"dl_info_speed"`
	DlRateLimit       int    `json:"dl_rate_limit"`
	UlInfoData        int    `json:"up_info_data"`
	UlInfoSpeed       int    `json:"up_info_speed"`
	UlRateLimit       int    `json:"up_rate_limit"`
	Queueing          bool   `json:"queueing"`
	UseAltSpeedLimits bool   `json:"use_alt_speed_limits"`
	RefreshInterval   int    `json:"refresh_interval"`
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

// Categories mapping
type Categories struct {
	Category map[string]Category
}

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
