package qbt

// Torrent creator format for api/v2/torrentcreator/addTask (qBittorrent built with libtorrent 2.x).
const (
	TorrentCreatorFormatV1     = "v1"
	TorrentCreatorFormatV2     = "v2"
	TorrentCreatorFormatHybrid = "hybrid"
)

// TorrentCreatorAddTaskOptions configures api/v2/torrentcreator/addTask.
// Trackers and URLSeeds are encoded like the WebUI (each entry URL-encoded, joined with "|").
type TorrentCreatorAddTaskOptions struct {
	SourcePath string
	Private    *bool
	// Format is one of TorrentCreatorFormat* (libtorrent 2.x); leave empty for server default (hybrid).
	Format string
	// PieceSize is piece length in bytes; 0 means automatic (optional).
	PieceSize *int
	// TorrentFilePath is where to write the generated .torrent (optional).
	TorrentFilePath string
	Comment         string
	Source          string
	// Trackers lists tracker URLs; use one slice element per line (empty strings preserve tracker tiers).
	Trackers []string
	URLSeeds []string
	// StartSeeding: if nil, server defaults to true when TorrentFilePath is empty, else false.
	StartSeeding *bool
	// OptimizeAlignment and PaddedFileSizeLimit apply to libtorrent 1.x builds; ignored on libtorrent 2.x.
	OptimizeAlignment   *bool
	PaddedFileSizeLimit *int
}

// TorrentCreatorTaskStatus is one object from api/v2/torrentcreator/status.
type TorrentCreatorTaskStatus struct {
	TaskID              string   `json:"taskID"`
	SourcePath          string   `json:"sourcePath"`
	PieceSize           int      `json:"pieceSize"`
	Private             bool     `json:"private"`
	Format              string   `json:"format,omitempty"`
	OptimizeAlignment   *bool    `json:"optimizeAlignment,omitempty"`
	PaddedFileSizeLimit *int     `json:"paddedFileSizeLimit,omitempty"`
	Status              string   `json:"status"`
	Comment             string   `json:"comment,omitempty"`
	TorrentFilePath     string   `json:"torrentFilePath,omitempty"`
	Source              string   `json:"source,omitempty"`
	Trackers            []string `json:"trackers,omitempty"`
	URLSeeds            []string `json:"urlSeeds,omitempty"`
	TimeAdded           string   `json:"timeAdded,omitempty"`
	TimeStarted         string   `json:"timeStarted,omitempty"`
	TimeFinished        string   `json:"timeFinished,omitempty"`
	ErrorMessage        string   `json:"errorMessage,omitempty"`
	Progress            float64  `json:"progress,omitempty"`
}
