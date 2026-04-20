package qbt

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
	AddStoppedEnabled                  bool                   `json:"add_stopped_enabled"`
	AddToTopOfQueue                    bool                   `json:"add_to_top_of_queue"`
	AddTrackers                        string                 `json:"add_trackers"`
	AddTrackersEnabled                 bool                   `json:"add_trackers_enabled"`
	AddTrackersFromURLEnabled          bool                   `json:"add_trackers_from_url_enabled"`
	AddTrackersURL                     string                 `json:"add_trackers_url"`
	AddTrackersURLList                 string                 `json:"add_trackers_url_list"`
	AltDlLimit                         int                    `json:"alt_dl_limit"`
	AltUpLimit                         int                    `json:"alt_up_limit"`
	AlternativeWebuiEnabled            bool                   `json:"alternative_webui_enabled"`
	AlternativeWebuiPath               string                 `json:"alternative_webui_path"`
	AnnounceIP                         string                 `json:"announce_ip"`
	AnnouncePort                       int                    `json:"announce_port"`
	AnnounceToAllTiers                 bool                   `json:"announce_to_all_tiers"`
	AnnounceToAllTrackers              bool                   `json:"announce_to_all_trackers"`
	AnonymousMode                      bool                   `json:"anonymous_mode"`
	AppInstanceName                    string                 `json:"app_instance_name"`
	AsyncIoThreads                     int                    `json:"async_io_threads"`
	AutoDeleteMode                     int                    `json:"auto_delete_mode"`
	AutoTmmEnabled                     bool                   `json:"auto_tmm_enabled"`
	AutorunEnabled                     bool                   `json:"autorun_enabled"`
	AutorunOnTorrentAddedEnabled       bool                   `json:"autorun_on_torrent_added_enabled"`
	AutorunOnTorrentAddedProgram       string                 `json:"autorun_on_torrent_added_program"`
	AutorunProgram                     string                 `json:"autorun_program"`
	BannedIPs                          string                 `json:"banned_IPs"`
	BdecodeDepthLimit                  int                    `json:"bdecode_depth_limit"`
	BdecodeTokenLimit                  int                    `json:"bdecode_token_limit"`
	BittorrentProtocol                 int                    `json:"bittorrent_protocol"`
	BlockPeersOnPrivilegedPorts        bool                   `json:"block_peers_on_privileged_ports"`
	BypassAuthSubnetWhitelist          string                 `json:"bypass_auth_subnet_whitelist"`
	BypassAuthSubnetWhitelistEnabled   bool                   `json:"bypass_auth_subnet_whitelist_enabled"`
	BypassLocalAuth                    bool                   `json:"bypass_local_auth"`
	CategoryChangedTmmEnabled          bool                   `json:"category_changed_tmm_enabled"`
	CheckingMemoryUse                  int                    `json:"checking_memory_use"`
	ConfirmTorrentDeletion             bool                   `json:"confirm_torrent_deletion"`
	ConfirmTorrentRecheck              bool                   `json:"confirm_torrent_recheck"`
	ConnectionSpeed                    int                    `json:"connection_speed"`
	CurrentInterfaceAddress            string                 `json:"current_interface_address"`
	CurrentInterfaceName               string                 `json:"current_interface_name"`
	CurrentNetworkInterface            string                 `json:"current_network_interface"`
	DeleteTorrentContentFiles          bool                   `json:"delete_torrent_content_files"`
	Dht                                bool                   `json:"dht"`
	DhtBootstrapNodes                  string                 `json:"dht_bootstrap_nodes"`
	DiskCache                          int                    `json:"disk_cache"`
	DiskCacheTtl                       int                    `json:"disk_cache_ttl"`
	DiskIoReadMode                     int                    `json:"disk_io_read_mode"`
	DiskIoType                         int                    `json:"disk_io_type"`
	DiskIoWriteMode                    int                    `json:"disk_io_write_mode"`
	DiskQueueSize                      int                    `json:"disk_queue_size"`
	DlLimit                            int                    `json:"dl_limit"`
	DontCountSlowTorrents              bool                   `json:"dont_count_slow_torrents"`
	DyndnsDomain                       string                 `json:"dyndns_domain"`
	DyndnsEnabled                      bool                   `json:"dyndns_enabled"`
	DyndnsPassword                     string                 `json:"dyndns_password"`
	DyndnsService                      int                    `json:"dyndns_service"`
	DyndnsUsername                     string                 `json:"dyndns_username"`
	EmbeddedTrackerPort                int                    `json:"embedded_tracker_port"`
	EmbeddedTrackerPortForwarding      bool                   `json:"embedded_tracker_port_forwarding"`
	EnableCoalesceReadWrite            bool                   `json:"enable_coalesce_read_write"`
	EnableEmbeddedTracker              bool                   `json:"enable_embedded_tracker"`
	EnableMultiConnectionsFromSameIp   bool                   `json:"enable_multi_connections_from_same_ip"`
	EnablePieceExtentAffinity          bool                   `json:"enable_piece_extent_affinity"`
	EnableUploadSuggestions            bool                   `json:"enable_upload_suggestions"`
	Encryption                         int                    `json:"encryption"`
	ExcludedFileNames                  string                 `json:"excluded_file_names"`
	ExcludedFileNamesEnabled           bool                   `json:"excluded_file_names_enabled"`
	ExportDir                          string                 `json:"export_dir"`
	ExportDirFin                       string                 `json:"export_dir_fin"`
	FileLogAge                         int                    `json:"file_log_age"`
	FileLogAgeType                     int                    `json:"file_log_age_type"`
	FileLogBackupEnabled               bool                   `json:"file_log_backup_enabled"`
	FileLogDeleteOld                   bool                   `json:"file_log_delete_old"`
	FileLogEnabled                     bool                   `json:"file_log_enabled"`
	FileLogMaxSize                     int                    `json:"file_log_max_size"`
	FileLogPath                        string                 `json:"file_log_path"`
	FilePoolSize                       int                    `json:"file_pool_size"`
	HashingThreads                     int                    `json:"hashing_threads"`
	HostnameCacheTTL                   int                    `json:"hostname_cache_ttl"`
	I2PAddress                         string                 `json:"i2p_address"`
	I2PEnabled                         bool                   `json:"i2p_enabled"`
	I2PInboundLength                   int                    `json:"i2p_inbound_length"`
	I2PInboundQuantity                 int                    `json:"i2p_inbound_quantity"`
	I2PMixedMode                       bool                   `json:"i2p_mixed_mode"`
	I2POutboundLength                  int                    `json:"i2p_outbound_length"`
	I2POutboundQuantity                int                    `json:"i2p_outbound_quantity"`
	I2PPort                            int                    `json:"i2p_port"`
	IdnSupportEnabled                  bool                   `json:"idn_support_enabled"`
	IgnoreSSLErrors                    bool                   `json:"ignore_ssl_errors"`
	IncompleteFilesExt                 bool                   `json:"incomplete_files_ext"`
	IpFilterEnabled                    bool                   `json:"ip_filter_enabled"`
	IpFilterPath                       string                 `json:"ip_filter_path"`
	IpFilterTrackers                   bool                   `json:"ip_filter_trackers"`
	LimitLanPeers                      bool                   `json:"limit_lan_peers"`
	LimitTcpOverhead                   bool                   `json:"limit_tcp_overhead"`
	LimitUtpRate                       bool                   `json:"limit_utp_rate"`
	ListenPort                         int                    `json:"listen_port"`
	Locale                             string                 `json:"locale"`
	Lsd                                bool                   `json:"lsd"`
	MailNotificationAuthEnabled        bool                   `json:"mail_notification_auth_enabled"`
	MailNotificationEmail              string                 `json:"mail_notification_email"`
	MailNotificationEnabled            bool                   `json:"mail_notification_enabled"`
	MailNotificationPassword           string                 `json:"mail_notification_password"`
	MailNotificationSender             string                 `json:"mail_notification_sender"`
	MailNotificationSmtp               string                 `json:"mail_notification_smtp"`
	MailNotificationSslEnabled         bool                   `json:"mail_notification_ssl_enabled"`
	MailNotificationUsername           string                 `json:"mail_notification_username"`
	MarkOfTheWeb                       bool                   `json:"mark_of_the_web"`
	MaxActiveCheckingTorrents          int                    `json:"max_active_checking_torrents"`
	MaxActiveDownloads                 int                    `json:"max_active_downloads"`
	MaxActiveTorrents                  int                    `json:"max_active_torrents"`
	MaxActiveUploads                   int                    `json:"max_active_uploads"`
	MaxConcurrentHttpAnnounces         int                    `json:"max_concurrent_http_announces"`
	MaxConnec                          int                    `json:"max_connec"`
	MaxConnecPerTorrent                int                    `json:"max_connec_per_torrent"`
	MaxInactiveSeedingTime             int                    `json:"max_inactive_seeding_time"`
	MaxInactiveSeedingTimeEnabled      bool                   `json:"max_inactive_seeding_time_enabled"`
	MaxRatio                           float64                `json:"max_ratio"`
	MaxRatioAct                        int                    `json:"max_ratio_act"`
	MaxRatioEnabled                    bool                   `json:"max_ratio_enabled"`
	MaxSeedingTime                     int                    `json:"max_seeding_time"`
	MaxSeedingTimeEnabled              bool                   `json:"max_seeding_time_enabled"`
	MaxUploads                         int                    `json:"max_uploads"`
	MaxUploadsPerTorrent               int                    `json:"max_uploads_per_torrent"`
	MemoryWorkingSetLimit              int                    `json:"memory_working_set_limit"`
	MergeTrackers                      bool                   `json:"merge_trackers"`
	OutgoingPortsMax                   int                    `json:"outgoing_ports_max"`
	OutgoingPortsMin                   int                    `json:"outgoing_ports_min"`
	PeerTos                            int                    `json:"peer_tos"`
	PeerTurnover                       int                    `json:"peer_turnover"`
	PeerTurnoverCutoff                 int                    `json:"peer_turnover_cutoff"`
	PeerTurnoverInterval               int                    `json:"peer_turnover_interval"`
	PerformanceWarning                 bool                   `json:"performance_warning"`
	Pex                                bool                   `json:"pex"`
	PreallocateAll                     bool                   `json:"preallocate_all"`
	ProxyAuthEnabled                   bool                   `json:"proxy_auth_enabled"`
	ProxyBittorrent                    bool                   `json:"proxy_bittorrent"`
	ProxyHostnameLookup                bool                   `json:"proxy_hostname_lookup"`
	ProxyIp                            string                 `json:"proxy_ip"`
	ProxyMisc                          bool                   `json:"proxy_misc"`
	ProxyPassword                      string                 `json:"proxy_password"`
	ProxyPeerConnections               bool                   `json:"proxy_peer_connections"`
	ProxyPort                          int                    `json:"proxy_port"`
	ProxyRss                           bool                   `json:"proxy_rss"`
	ProxyType                          string                 `json:"proxy_type"`
	ProxyUsername                      string                 `json:"proxy_username"`
	PythonExecutablePath               string                 `json:"python_executable_path"`
	QueueingEnabled                    bool                   `json:"queueing_enabled"`
	RandomPort                         bool                   `json:"random_port"`
	ReannounceWhenAddressChanged       bool                   `json:"reannounce_when_address_changed"`
	RecheckCompletedTorrents           bool                   `json:"recheck_completed_torrents"`
	RefreshInterval                    int                    `json:"refresh_interval"`
	RequestQueueSize                   int                    `json:"request_queue_size"`
	ResolvePeerCountries               bool                   `json:"resolve_peer_countries"`
	ResolvePeerHostNames               bool                   `json:"resolve_peer_host_names"`
	ResumeDataStorageType              string                 `json:"resume_data_storage_type"`
	RssAutoDownloadingEnabled          bool                   `json:"rss_auto_downloading_enabled"`
	RssDownloadRepackProperEpisodes    bool                   `json:"rss_download_repack_proper_episodes"`
	RssFetchDelay                      int64                  `json:"rss_fetch_delay"`
	RssMaxArticlesPerFeed              int                    `json:"rss_max_articles_per_feed"`
	RssProcessingEnabled               bool                   `json:"rss_processing_enabled"`
	RssRefreshInterval                 int                    `json:"rss_refresh_interval"`
	RssSmartEpisodeFilters             string                 `json:"rss_smart_episode_filters"`
	SavePath                           string                 `json:"save_path"`
	SavePathChangedTmmEnabled          bool                   `json:"save_path_changed_tmm_enabled"`
	SaveResumeDataInterval             int                    `json:"save_resume_data_interval"`
	SaveStatisticsInterval             int                    `json:"save_statistics_interval"`
	ScanDirs                           map[string]interface{} `json:"scan_dirs"`
	ScheduleFromHour                   int                    `json:"schedule_from_hour"`
	ScheduleFromMin                    int                    `json:"schedule_from_min"`
	ScheduleToHour                     int                    `json:"schedule_to_hour"`
	ScheduleToMin                      int                    `json:"schedule_to_min"`
	SchedulerDays                      int                    `json:"scheduler_days"`
	SchedulerEnabled                   bool                   `json:"scheduler_enabled"`
	SendBufferLowWatermark             int                    `json:"send_buffer_low_watermark"`
	SendBufferWatermark                int                    `json:"send_buffer_watermark"`
	SendBufferWatermarkFactor          int                    `json:"send_buffer_watermark_factor"`
	ShareLimitsMode                    string                 `json:"share_limits_mode"`
	SlowTorrentDlRateThreshold         int                    `json:"slow_torrent_dl_rate_threshold"`
	SlowTorrentInactiveTimer           int                    `json:"slow_torrent_inactive_timer"`
	SlowTorrentUlRateThreshold         int                    `json:"slow_torrent_ul_rate_threshold"`
	SocketBacklogSize                  int                    `json:"socket_backlog_size"`
	SocketReceiveBufferSize            int                    `json:"socket_receive_buffer_size"`
	SocketSendBufferSize               int                    `json:"socket_send_buffer_size"`
	SsrfMitigation                     bool                   `json:"ssrf_mitigation"`
	SslEnabled                         bool                   `json:"ssl_enabled"`
	SslListenPort                      int                    `json:"ssl_listen_port"`
	StatusBarExternalIP                bool                   `json:"status_bar_external_ip"`
	StopTrackerTimeout                 int                    `json:"stop_tracker_timeout"`
	TempPath                           string                 `json:"temp_path"`
	TempPathEnabled                    bool                   `json:"temp_path_enabled"`
	TorrentChangedTmmEnabled           bool                   `json:"torrent_changed_tmm_enabled"`
	TorrentContentLayout               string                 `json:"torrent_content_layout"`
	TorrentContentRemoveOption         string                 `json:"torrent_content_remove_option"`
	TorrentFileSizeLimit               int                    `json:"torrent_file_size_limit"`
	TorrentStopCondition               string                 `json:"torrent_stop_condition"`
	UpLimit                            int                    `json:"up_limit"`
	UploadChokingAlgorithm             int                    `json:"upload_choking_algorithm"`
	UploadSlotsBehavior                int                    `json:"upload_slots_behavior"`
	Upnp                               bool                   `json:"upnp"`
	UpnpLeaseDuration                  int                    `json:"upnp_lease_duration"`
	UseCategoryPathsInManualMode       bool                   `json:"use_category_paths_in_manual_mode"`
	UseHttps                           bool                   `json:"use_https"`
	UseUnwantedFolder                  bool                   `json:"use_unwanted_folder"`
	UtpTcpMixedMode                    int                    `json:"utp_tcp_mixed_mode"`
	ValidateHttpsTrackerCertificate    bool                   `json:"validate_https_tracker_certificate"`
	WebUiAddress                       string                 `json:"web_ui_address"`
	WebUiAPIKey                        string                 `json:"web_ui_api_key"`
	WebUiBanDuration                   int                    `json:"web_ui_ban_duration"`
	WebUiClickjackingProtectionEnabled bool                   `json:"web_ui_clickjacking_protection_enabled"`
	WebUiCsrfProtectionEnabled         bool                   `json:"web_ui_csrf_protection_enabled"`
	WebUiCustomHttpHeaders             string                 `json:"web_ui_custom_http_headers"`
	WebUiDomainList                    string                 `json:"web_ui_domain_list"`
	WebUiHostHeaderValidationEnabled   bool                   `json:"web_ui_host_header_validation_enabled"`
	WebUiHttpsCertPath                 string                 `json:"web_ui_https_cert_path"`
	WebUiHttpsKeyPath                  string                 `json:"web_ui_https_key_path"`
	WebUiMaxAuthFailCount              int                    `json:"web_ui_max_auth_fail_count"`
	WebUiPort                          int                    `json:"web_ui_port"`
	WebUiReverseProxiesList            string                 `json:"web_ui_reverse_proxies_list"`
	WebUiReverseProxyEnabled           bool                   `json:"web_ui_reverse_proxy_enabled"`
	WebUiSecureCookieEnabled           bool                   `json:"web_ui_secure_cookie_enabled"`
	WebUiSessionTimeout                int                    `json:"web_ui_session_timeout"`
	WebUiUpnp                          bool                   `json:"web_ui_upnp"`
	WebUiUseCustomHttpHeadersEnabled   bool                   `json:"web_ui_use_custom_http_headers_enabled"`
	WebUiUsername                      string                 `json:"web_ui_username"`
}

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
