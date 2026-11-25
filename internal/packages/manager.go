package packages

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"ssh-packet-capture/internal/models"
	"ssh-packet-capture/internal/storage"
)

//go:embed bins/*.gz
var builtinBins embed.FS

type builtinEntry struct {
	pkg       models.OfflinePackage
	embedPath string
}

// Manager manages built-in and user-imported offline tcpdump packages.
type Manager struct {
	mu           sync.RWMutex
	builtins     []builtinEntry
	customDir    string
	manifestPath string
	customs      []models.OfflinePackage
}

func NewManager() (*Manager, error) {
	cfgDir, err := storage.AppConfigDir()
	if err != nil {
		return nil, err
	}
	customDir := filepath.Join(cfgDir, "offline_packages")
	if err := os.MkdirAll(customDir, 0o755); err != nil {
		return nil, err
	}

	m := &Manager{
		customDir:    customDir,
		manifestPath: filepath.Join(customDir, "manifest.json"),
		customs:      []models.OfflinePackage{},
	}
	m.initBuiltins()
	_ = m.loadCustomManifest()
	return m, nil
}

func (m *Manager) initBuiltins() {
	defs := []struct {
		id        string
		name      string
		arch      string
		embedPath string
		desc      string
		osTypes   []string
	}{
		{
			id:        "builtin-x86_64-static",
			name:      "tcpdump 4.9.3 (Linux x86_64 静态通用版)",
			arch:      "x86_64",
			embedPath: "bins/tcpdump-4.9.3-x86_64.gz",
			osTypes:   []string{"linux-generic", "ubuntu", "debian", "centos", "rhel", "rocky", "almalinux", "alpine", "openeuler", "kylin", "uos"},
			desc:      "静态编译无依赖，适用于绝大多数 64 位 x86_64/amd64 Linux 发行版（CentOS/Ubuntu/Debian/Rocky/Alpine/麒麟/欧拉等）",
		},
		{
			id:        "builtin-aarch64-static",
			name:      "tcpdump 4.9.3 (Linux ARM64 / aarch64 静态通用版)",
			arch:      "aarch64",
			embedPath: "bins/tcpdump-4.9.3-aarch64.gz",
			osTypes:   []string{"linux-generic", "ubuntu", "debian", "centos", "rhel", "rocky", "alpine", "openeuler", "kylin", "uos"},
			desc:      "静态编译无依赖，适用于 ARM64/aarch64 服务器与边缘设备（鲲鹏/飞腾/Graviton/树莓派64位等）",
		},
		{
			id:        "builtin-armhf-static",
			name:      "tcpdump 4.9.3 (Linux ARMv7 / armhf 静态通用版)",
			arch:      "armhf",
			embedPath: "bins/tcpdump-4.9.3-armhf.gz",
			osTypes:   []string{"linux-generic", "debian", "ubuntu", "alpine", "openwrt"},
			desc:      "静态编译无依赖，适用于 32 位 ARMv7 / armhf 嵌入式 Linux、网关及树莓派 32 位系统",
		},
		{
			id:        "builtin-x86-static",
			name:      "tcpdump 4.9.3 (Linux x86 / i386 静态通用版)",
			arch:      "x86",
			embedPath: "bins/tcpdump-4.9.3-x86.gz",
			osTypes:   []string{"linux-generic", "centos", "ubuntu", "debian", "alpine"},
			desc:      "静态编译无依赖，适用于传统 32 位 x86 / i386 / i686 Linux 服务器",
		},
	}

	for _, d := range defs {
		rawGz, err := builtinBins.ReadFile(d.embedPath)
		if err != nil {
			continue
		}
		gr, err := gzip.NewReader(bytes.NewReader(rawGz))
		if err != nil {
			continue
		}
		h := sha256.New()
		n, err := io.Copy(h, gr)
		_ = gr.Close()
		if err != nil {
			continue
		}
		m.builtins = append(m.builtins, builtinEntry{
			embedPath: d.embedPath,
			pkg: models.OfflinePackage{
				ID:          d.id,
				Name:        d.name,
				Version:     "4.9.3",
				Arch:        d.arch,
				OSTypes:     d.osTypes,
				Format:      "static-bin",
				Size:        n,
				SHA256:      hex.EncodeToString(h.Sum(nil))[:16],
				Builtin:     true,
				FileName:    strings.TrimSuffix(filepath.Base(d.embedPath), ".gz"),
				Description: d.desc,
			},
		})
	}
}

func (m *Manager) loadCustomManifest() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var list []models.OfflinePackage
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	m.customs = list
	return nil
}

func (m *Manager) saveCustomManifestLocked() error {
	data, err := json.MarshalIndent(m.customs, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.manifestPath, data, 0o644)
}

// NormalizeArch converts uname -m outputs into canonical architecture keys.
func NormalizeArch(raw string) string {
	a := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case a == "x86_64" || a == "amd64" || a == "x64":
		return "x86_64"
	case a == "aarch64" || a == "arm64" || a == "armv8" || a == "armv8l":
		return "aarch64"
	case strings.HasPrefix(a, "armv7") || strings.HasPrefix(a, "armv6") || a == "armhf" || a == "armel" || a == "arm":
		return "armhf"
	case a == "i386" || a == "i686" || a == "i586" || a == "x86":
		return "x86"
	default:
		return a
	}
}

// ListPackages returns all built-in and custom offline packages.
func (m *Manager) ListPackages() []models.OfflinePackage {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]models.OfflinePackage, 0, len(m.builtins)+len(m.customs))
	for _, b := range m.builtins {
		out = append(out, b.pkg)
	}
	out = append(out, m.customs...)
	return out
}

// MatchPackage selects the best offline package for the target architecture and OS ID.
func (m *Manager) MatchPackage(rawArch string, osID string) *models.OfflinePackage {
	m.mu.RLock()
	defer m.mu.RUnlock()

	arch := NormalizeArch(rawArch)
	osLower := strings.ToLower(strings.TrimSpace(osID))

	// 1. Prefer a custom package matching both arch and exact OS ID
	for _, c := range m.customs {
		if NormalizeArch(c.Arch) == arch && osMatches(c.OSTypes, osLower, false) {
			cp := c
			return &cp
		}
	}
	// 2. Match built-in static binary by architecture
	for _, b := range m.builtins {
		if NormalizeArch(b.pkg.Arch) == arch {
			cp := b.pkg
			return &cp
		}
	}
	// 3. Fallback to any custom package matching arch + generic linux
	for _, c := range m.customs {
		if NormalizeArch(c.Arch) == arch {
			cp := c
			return &cp
		}
	}
	return nil
}

func osMatches(osTypes []string, osID string, allowGeneric bool) bool {
	if osID == "" {
		return allowGeneric
	}
	for _, t := range osTypes {
		tl := strings.ToLower(strings.TrimSpace(t))
		if tl == osID {
			return true
		}
		if allowGeneric && (tl == "linux-generic" || tl == "all" || tl == "*") {
			return true
		}
	}
	return false
}

// OpenPackage opens a readable stream for the given package ID (decompressed if built-in).
func (m *Manager) OpenPackage(pkgID string) (io.ReadCloser, models.OfflinePackage, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, b := range m.builtins {
		if b.pkg.ID == pkgID {
			rawGz, err := builtinBins.ReadFile(b.embedPath)
			if err != nil {
				return nil, models.OfflinePackage{}, err
			}
			gr, err := gzip.NewReader(bytes.NewReader(rawGz))
			if err != nil {
				return nil, models.OfflinePackage{}, err
			}
			return gr, b.pkg, nil
		}
	}

	for _, c := range m.customs {
		if c.ID == pkgID {
			fp := filepath.Join(m.customDir, c.FileName)
			f, err := os.Open(fp)
			if err != nil {
				return nil, models.OfflinePackage{}, fmt.Errorf("无法打开自定义离线包文件: %w", err)
			}
			return f, c, nil
		}
	}

	return nil, models.OfflinePackage{}, fmt.Errorf("未找到离线包: %s", pkgID)
}

// ImportPackage copies a user-selected offline package into local storage and registers it.
func (m *Manager) ImportPackage(srcPath, name, version, arch, format string, osTypes []string, desc string) (models.OfflinePackage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	src, err := os.Open(srcPath)
	if err != nil {
		return models.OfflinePackage{}, fmt.Errorf("打开源文件失败: %w", err)
	}
	defer src.Close()

	idBytes := make([]byte, 6)
	_, _ = rand.Read(idBytes)
	id := "custom-" + hex.EncodeToString(idBytes)

	baseName := filepath.Base(srcPath)
	storedName := id + "_" + baseName
	dstPath := filepath.Join(m.customDir, storedName)

	dst, err := os.Create(dstPath)
	if err != nil {
		return models.OfflinePackage{}, fmt.Errorf("创建目标文件失败: %w", err)
	}
	defer dst.Close()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), src)
	if err != nil {
		_ = os.Remove(dstPath)
		return models.OfflinePackage{}, fmt.Errorf("复制文件失败: %w", err)
	}

	if name == "" {
		name = baseName
	}
	if version == "" {
		version = "custom"
	}
	if format == "" {
		format = detectFormat(baseName)
	}
	if len(osTypes) == 0 {
		osTypes = []string{"linux-generic"}
	}

	pkg := models.OfflinePackage{
		ID:          id,
		Name:        name,
		Version:     version,
		Arch:        NormalizeArch(arch),
		OSTypes:     osTypes,
		Format:      format,
		Size:        n,
		SHA256:      hex.EncodeToString(h.Sum(nil))[:16],
		Builtin:     false,
		FileName:    storedName,
		Description: desc,
	}

	m.customs = append(m.customs, pkg)
	if err := m.saveCustomManifestLocked(); err != nil {
		return pkg, err
	}
	return pkg, nil
}

// DeleteCustomPackage removes a user-imported package.
func (m *Manager) DeleteCustomPackage(pkgID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	next := make([]models.OfflinePackage, 0, len(m.customs))
	var removed *models.OfflinePackage
	for i := range m.customs {
		if m.customs[i].ID == pkgID {
			cp := m.customs[i]
			removed = &cp
			continue
		}
		next = append(next, m.customs[i])
	}
	if removed == nil {
		return fmt.Errorf("内置离线包不可删除或未找到该包")
	}
	_ = os.Remove(filepath.Join(m.customDir, removed.FileName))
	m.customs = next
	return m.saveCustomManifestLocked()
}

func detectFormat(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".rpm"):
		return "rpm"
	case strings.HasSuffix(lower, ".deb"):
		return "deb"
	case strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz"):
		return "tar.gz"
	default:
		return "static-bin"
	}
}
