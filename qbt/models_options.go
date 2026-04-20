package qbt

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
