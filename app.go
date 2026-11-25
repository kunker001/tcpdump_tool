package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"ssh-packet-capture/internal/models"
	"ssh-packet-capture/internal/packages"
	"ssh-packet-capture/internal/pcap"
	"ssh-packet-capture/internal/sshclient"
	"ssh-packet-capture/internal/storage"
)

const maxStoredPackets = 20000

// App is the main Wails application backend struct.
type App struct {
	ctx      context.Context
	profiles *storage.ProfileStore
	pkgMgr   *packages.Manager
	sshCli   *sshclient.Client

	pktMu      sync.RWMutex
	pcapHeader *pcap.GlobalHeader
	packets    []*pcap.RawPacket
	stats      models.CaptureStats
	startTime  time.Time

	logMu sync.Mutex
	logs  []models.LogEntry
	logID int
}

func NewApp() *App {
	ps, _ := storage.NewProfileStore()
	pm, _ := packages.NewManager()
	return &App{
		profiles: ps,
		pkgMgr:   pm,
		sshCli:   sshclient.NewClient(),
		packets:  make([]*pcap.RawPacket, 0, 1024),
		stats: models.CaptureStats{
			Protocols: map[string]int{},
		},
		logs: make([]models.LogEntry, 0, 128),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.addLog("info", "系统", "NetProbe SSH 远程抓包工具已启动，内置 4 个跨架构静态 tcpdump 离线包")
}

func (a *App) shutdown(ctx context.Context) {
	a.sshCli.Disconnect()
}

// --- Logging ---

func (a *App) addLog(level, source, message string) {
	a.logMu.Lock()
	a.logID++
	entry := models.LogEntry{
		ID:      a.logID,
		Time:    time.Now().Format("15:04:05"),
		Level:   level,
		Source:  source,
		Message: message,
	}
	a.logs = append(a.logs, entry)
	if len(a.logs) > 500 {
		a.logs = a.logs[len(a.logs)-500:]
	}
	a.logMu.Unlock()

	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "log:entry", entry)
	}
}

func (a *App) GetLogs() []models.LogEntry {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	out := make([]models.LogEntry, len(a.logs))
	copy(out, a.logs)
	return out
}

func (a *App) ClearLogs() {
	a.logMu.Lock()
	a.logs = a.logs[:0]
	a.logMu.Unlock()
}

// --- Server Profiles ---

func (a *App) ListProfiles() []models.ServerProfile {
	if a.profiles == nil {
		return []models.ServerProfile{}
	}
	return a.profiles.List()
}

func (a *App) SaveProfile(p models.ServerProfile) (models.ServerProfile, error) {
	saved, err := a.profiles.Save(p)
	if err != nil {
		return saved, err
	}
	a.addLog("info", "服务器", fmt.Sprintf("已保存服务器配置: %s (%s:%d)", saved.Name, saved.Host, saved.Port))
	return saved, nil
}

func (a *App) DeleteProfile(id string) error {
	if err := a.profiles.Delete(id); err != nil {
		return err
	}
	a.addLog("info", "服务器", "已删除服务器配置")
	return nil
}

// --- SSH Connection & Environment ---

func (a *App) ConnectServer(p models.ServerProfile) (models.ServerEnvInfo, error) {
	a.addLog("info", "SSH", fmt.Sprintf("正在连接 %s@%s:%d ...", p.Username, p.Host, p.Port))
	env, err := a.sshCli.Connect(p, a.pkgMgr)
	if err != nil {
		a.addLog("error", "SSH", err.Error())
		return env, err
	}

	if p.ID != "" && a.profiles != nil {
		p.LastConnectedAt = time.Now().Format("2006-01-02 15:04:05")
		_, _ = a.profiles.Save(p)
	}

	if env.HasTcpdump {
		a.addLog("success", "SSH", fmt.Sprintf("已连接 %s | %s (%s) | tcpdump 已就绪 (%s)", env.Host, env.OSName, env.Arch, env.TcpdumpPath))
	} else {
		a.addLog("warn", "SSH", fmt.Sprintf("已连接 %s | %s (%s) | 未检测到 tcpdump，可使用自动离线安装", env.Host, env.OSName, env.Arch))
	}
	return env, nil
}

func (a *App) DisconnectServer() {
	env := a.sshCli.CurrentEnv()
	a.sshCli.Disconnect()
	a.pktMu.Lock()
	a.stats.Running = false
	a.pktMu.Unlock()
	if env.Connected {
		a.addLog("info", "SSH", fmt.Sprintf("已断开与 %s 的连接", env.Host))
	}
}

func (a *App) GetServerEnv() models.ServerEnvInfo {
	return a.sshCli.CurrentEnv()
}

func (a *App) RefreshServerEnv() (models.ServerEnvInfo, error) {
	env, err := a.sshCli.RefreshEnv(a.pkgMgr)
	if err != nil {
		a.addLog("error", "SSH", err.Error())
		return env, err
	}
	return env, nil
}

// --- Offline Packages & Auto-Installer ---

func (a *App) ListOfflinePackages() []models.OfflinePackage {
	if a.pkgMgr == nil {
		return []models.OfflinePackage{}
	}
	return a.pkgMgr.ListPackages()
}

func (a *App) SelectFileForDialog(title string, filterDisplay string, filterPattern string) (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: title,
		Filters: []runtime.FileFilter{
			{DisplayName: filterDisplay, Pattern: filterPattern},
			{DisplayName: "所有文件 (*.*)", Pattern: "*.*"},
		},
	})
}

func (a *App) ImportOfflinePackage(srcPath, name, version, arch, format string, osTypes []string, desc string) (models.OfflinePackage, error) {
	pkg, err := a.pkgMgr.ImportPackage(srcPath, name, version, arch, format, osTypes, desc)
	if err != nil {
		a.addLog("error", "离线库", err.Error())
		return pkg, err
	}
	a.addLog("success", "离线库", fmt.Sprintf("已导入自定义离线包: %s (%s / %s)", pkg.Name, pkg.Arch, pkg.Format))
	return pkg, nil
}

func (a *App) DeleteOfflinePackage(pkgID string) error {
	if err := a.pkgMgr.DeleteCustomPackage(pkgID); err != nil {
		return err
	}
	a.addLog("info", "离线库", "已删除自定义离线包")
	return nil
}

func (a *App) AutoInstallTcpdump(packageID string) (models.ServerEnvInfo, error) {
	env := a.sshCli.CurrentEnv()
	if !env.Connected {
		return env, fmt.Errorf("请先连接 SSH 服务器")
	}

	targetID := packageID
	if targetID == "" {
		matched := a.pkgMgr.MatchPackage(env.NormalizedArch, env.OSID)
		if matched == nil {
			return env, fmt.Errorf("未找到适配架构 %s (%s) 的离线包，请在「离线安装库」中导入对应安装包", env.Arch, env.OSName)
		}
		targetID = matched.ID
	}

	reader, pkg, err := a.pkgMgr.OpenPackage(targetID)
	if err != nil {
		a.addLog("error", "离线安装", err.Error())
		return env, err
	}
	defer reader.Close()

	a.addLog("info", "离线安装", fmt.Sprintf("开始自动离线安装: %s -> %s", pkg.Name, env.Host))

	newEnv, err := a.sshCli.InstallTcpdumpOffline(pkg, reader, a.pkgMgr, func(prog models.InstallProgress) {
		if a.ctx != nil {
			runtime.EventsEmit(a.ctx, "install:progress", prog)
		}
	})
	if err != nil {
		a.addLog("error", "离线安装", err.Error())
		return newEnv, err
	}

	a.addLog("success", "离线安装", fmt.Sprintf("tcpdump 离线安装成功: %s (%s)", newEnv.TcpdumpPath, newEnv.TcpdumpVersion))
	return newEnv, nil
}

// --- Packet Capture ---

func (a *App) StartCapture(cfg models.CaptureConfig) (string, error) {
	a.pktMu.Lock()
	a.pcapHeader = nil
	a.packets = a.packets[:0]
	a.startTime = time.Now()
	a.stats = models.CaptureStats{
		Running:   true,
		Protocols: map[string]int{},
	}
	a.pktMu.Unlock()

	var batchMu sync.Mutex
	batch := make([]models.PacketSummary, 0, 64)
	stopFlusher := make(chan struct{})

	// Periodic UI batch emitter (every 120ms) for smooth high-throughput rendering
	go func() {
		ticker := time.NewTicker(120 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				batchMu.Lock()
				var toSend []models.PacketSummary
				if len(batch) > 0 {
					toSend = batch
					batch = make([]models.PacketSummary, 0, 64)
				}
				batchMu.Unlock()

				if len(toSend) > 0 && a.ctx != nil {
					runtime.EventsEmit(a.ctx, "capture:packets", toSend)
				}
				if a.ctx != nil {
					runtime.EventsEmit(a.ctx, "capture:stats", a.GetCaptureStats())
				}
			case <-stopFlusher:
				batchMu.Lock()
				toSend := batch
				batch = nil
				batchMu.Unlock()
				if len(toSend) > 0 && a.ctx != nil {
					runtime.EventsEmit(a.ctx, "capture:packets", toSend)
				}
				return
			}
		}
	}()

	cmdDisplay, err := a.sshCli.StartCapture(
		cfg,
		func(hdr pcap.GlobalHeader) {
			a.pktMu.Lock()
			h := hdr
			a.pcapHeader = &h
			a.pktMu.Unlock()
		},
		func(pkt *pcap.RawPacket) {
			a.pktMu.Lock()
			if len(a.packets) < maxStoredPackets {
				a.packets = append(a.packets, pkt)
			}
			a.stats.TotalPackets++
			a.stats.TotalBytes += int64(pkt.OrigLen)
			a.stats.Protocols[pkt.Summary.Protocol]++
			a.pktMu.Unlock()

			batchMu.Lock()
			batch = append(batch, pkt.Summary)
			batchMu.Unlock()
		},
		func(stderrLine string) {
			a.addLog("info", "tcpdump", stderrLine)
		},
		func(doneErr error) {
			close(stopFlusher)
			a.pktMu.Lock()
			a.stats.Running = false
			a.pktMu.Unlock()

			if doneErr != nil {
				a.addLog("error", "抓包", doneErr.Error())
				if a.ctx != nil {
					runtime.EventsEmit(a.ctx, "capture:error", doneErr.Error())
				}
			} else {
				a.addLog("info", "抓包", fmt.Sprintf("抓包已停止，共捕获 %d 个数据包", a.GetCaptureStats().TotalPackets))
			}
			if a.ctx != nil {
				runtime.EventsEmit(a.ctx, "capture:stopped", a.GetCaptureStats())
			}
		},
	)

	if err != nil {
		close(stopFlusher)
		a.pktMu.Lock()
		a.stats.Running = false
		a.pktMu.Unlock()
		a.addLog("error", "抓包", err.Error())
		return "", err
	}

	a.pktMu.Lock()
	a.stats.Command = cmdDisplay
	a.pktMu.Unlock()

	a.addLog("success", "抓包", fmt.Sprintf("开始抓包: %s", cmdDisplay))
	return cmdDisplay, nil
}

func (a *App) StopCapture() {
	a.sshCli.StopCapture()
}

func (a *App) ClearPackets() {
	a.pktMu.Lock()
	a.packets = a.packets[:0]
	running := a.stats.Running
	cmd := a.stats.Command
	a.stats = models.CaptureStats{
		Running:   running,
		Protocols: map[string]int{},
		Command:   cmd,
	}
	if running {
		a.startTime = time.Now()
	}
	a.pktMu.Unlock()
}

func (a *App) GetCaptureStats() models.CaptureStats {
	a.pktMu.RLock()
	defer a.pktMu.RUnlock()

	st := a.stats
	st.Protocols = make(map[string]int, len(a.stats.Protocols))
	for k, v := range a.stats.Protocols {
		st.Protocols[k] = v
	}
	if !a.startTime.IsZero() && (st.Running || st.TotalPackets > 0) {
		elapsed := time.Since(a.startTime).Seconds()
		if elapsed < 0.1 {
			elapsed = 0.1
		}
		st.ElapsedSec = elapsed
		st.PacketsPerSec = float64(st.TotalPackets) / elapsed
		st.BytesPerSec = float64(st.TotalBytes) / elapsed
	}
	return st
}

func (a *App) GetPacketDetail(packetNo int) (models.PacketDetail, error) {
	a.pktMu.RLock()
	defer a.pktMu.RUnlock()

	if packetNo <= 0 || packetNo > len(a.packets) {
		return models.PacketDetail{}, fmt.Errorf("未找到序号为 #%d 的数据包", packetNo)
	}
	pkt := a.packets[packetNo-1]
	return pcap.DissectPacket(pkt, true), nil
}

// ExportPcap saves all currently captured packets to a standard Wireshark-compatible .pcap file.
func (a *App) ExportPcap() (string, error) {
	a.pktMu.RLock()
	hasHdr := a.pcapHeader != nil
	count := len(a.packets)
	a.pktMu.RUnlock()

	if !hasHdr || count == 0 {
		return "", fmt.Errorf("当前没有可导出的数据包")
	}

	defaultName := fmt.Sprintf("capture_%s.pcap", time.Now().Format("20060102_150405"))
	savePath, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "导出 PCAP 数据包文件",
		DefaultFilename: defaultName,
		Filters: []runtime.FileFilter{
			{DisplayName: "Wireshark PCAP (*.pcap)", Pattern: "*.pcap"},
		},
	})
	if err != nil {
		return "", err
	}
	if savePath == "" {
		return "", nil // user cancelled
	}

	a.pktMu.RLock()
	defer a.pktMu.RUnlock()

	f, err := os.Create(savePath)
	if err != nil {
		return "", fmt.Errorf("创建文件失败: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(a.pcapHeader.Raw[:]); err != nil {
		return "", err
	}
	for _, p := range a.packets {
		if _, err := f.Write(p.HeaderRaw[:]); err != nil {
			return "", err
		}
		if _, err := f.Write(p.Data); err != nil {
			return "", err
		}
	}

	a.addLog("success", "导出", fmt.Sprintf("已导出 %d 个数据包至 %s", len(a.packets), savePath))
	return savePath, nil
}
