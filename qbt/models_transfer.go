package qbt

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
