package models

// ServerProfile represents a saved SSH server connection configuration.
type ServerProfile struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Username        string `json:"username"`
	AuthType        string `json:"authType"` // "password" | "key"
	Password        string `json:"password"`
	PrivateKeyPath  string `json:"privateKeyPath"`
	Passphrase      string `json:"passphrase"`
	UseSudo         bool   `json:"useSudo"`
	SudoPassword    string `json:"sudoPassword"`
	Note            string `json:"note"`
	LastConnectedAt string `json:"lastConnectedAt"`
}

// NetInterface describes a network interface on the remote Linux host.
type NetInterface struct {
	Name        string `json:"name"`
	IP          string `json:"ip"`
	State       string `json:"state"`
	Description string `json:"description"`
}

// ServerEnvInfo holds detected remote system information after SSH connect.
type ServerEnvInfo struct {
	Connected        bool           `json:"connected"`
	ProfileID        string         `json:"profileId"`
	ProfileName      string         `json:"profileName"`
	Host             string         `json:"host"`
	Port             int            `json:"port"`
	Username         string         `json:"username"`
	OSName           string         `json:"osName"`
	OSID             string         `json:"osId"`
	OSVersion        string         `json:"osVersion"`
	Kernel           string         `json:"kernel"`
	Arch             string         `json:"arch"`
	NormalizedArch   string         `json:"normalizedArch"`
	HasTcpdump       bool           `json:"hasTcpdump"`
	TcpdumpPath      string         `json:"tcpdumpPath"`
	TcpdumpVersion   string         `json:"tcpdumpVersion"`
	IsRoot           bool           `json:"isRoot"`
	CanSudo          bool           `json:"canSudo"`
	Interfaces       []NetInterface `json:"interfaces"`
	MatchedPackageID string         `json:"matchedPackageId"`
}

// OfflinePackage describes a built-in or user-imported offline tcpdump package.
type OfflinePackage struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Arch        string   `json:"arch"`     // x86_64 | aarch64 | armhf | x86
	OSTypes     []string `json:"osTypes"`  // ["linux-generic"] or ["ubuntu","debian"] etc.
	Format      string   `json:"format"`   // static-bin | rpm | deb | tar.gz
	Size        int64    `json:"size"`
	SHA256      string   `json:"sha256"`
	Builtin     bool     `json:"builtin"`
	FileName    string   `json:"fileName"`
	Description string   `json:"description"`
}

// InstallProgress reports real-time progress during offline tcpdump installation.
type InstallProgress struct {
	Step       int    `json:"step"`       // 1..5
	TotalSteps int    `json:"totalSteps"` // 5
	Title      string `json:"title"`
	Detail     string `json:"detail"`
	Status     string `json:"status"` // "running" | "done" | "error"
	Percent    int    `json:"percent"`
}

// CaptureConfig specifies parameters for starting a remote tcpdump capture.
type CaptureConfig struct {
	Interface   string `json:"interface"`
	SrcIP       string `json:"srcIp"`
	DstIP       string `json:"dstIp"`
	Filter      string `json:"filter"`
	MaxPackets  int    `json:"maxPackets"`  // 0 = unlimited
	Snaplen     int    `json:"snaplen"`     // 0 = 65535 (full)
	ExcludeSSH  bool   `json:"excludeSsh"`  // auto append "not port <sshPort>"
	Promiscuous bool   `json:"promiscuous"` // false passes -p
}

// PacketSummary is the lightweight row data displayed in the packet table.
type PacketSummary struct {
	No        int    `json:"no"`
	Timestamp string `json:"timestamp"`
	SrcAddr   string `json:"srcAddr"`
	DstAddr   string `json:"dstAddr"`
	Protocol  string `json:"protocol"`
	Length    int    `json:"length"`
	Info      string `json:"info"`
}

// LayerField represents a single parsed key-value field in a protocol layer.
type LayerField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ProtocolLayer represents one protocol layer in the packet dissection tree.
type ProtocolLayer struct {
	Name    string       `json:"name"`
	Summary string       `json:"summary"`
	Fields  []LayerField `json:"fields"`
}

// HexLine represents one 16-byte line of hex + ASCII dump.
type HexLine struct {
	Offset string `json:"offset"`
	Hex    string `json:"hex"`
	ASCII  string `json:"ascii"`
}

// PacketDetail holds full dissected layers and hex dump for a selected packet.
type PacketDetail struct {
	Summary PacketSummary   `json:"summary"`
	Layers  []ProtocolLayer `json:"layers"`
	HexDump []HexLine       `json:"hexDump"`
	RawLen  int             `json:"rawLen"`
}

// CaptureStats tracks real-time capture metrics.
type CaptureStats struct {
	Running       bool           `json:"running"`
	TotalPackets  int            `json:"totalPackets"`
	TotalBytes    int64          `json:"totalBytes"`
	ElapsedSec    float64        `json:"elapsedSec"`
	PacketsPerSec float64        `json:"packetsPerSec"`
	BytesPerSec   float64        `json:"bytesPerSec"`
	Protocols     map[string]int `json:"protocols"`
	Command       string         `json:"command"`
}

// LogEntry records an operation log item for the UI activity log view.
type LogEntry struct {
	ID      int    `json:"id"`
	Time    string `json:"time"`
	Level   string `json:"level"` // info | success | warn | error
	Source  string `json:"source"`
	Message string `json:"message"`
}
