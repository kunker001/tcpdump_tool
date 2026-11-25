package sshclient

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"ssh-packet-capture/internal/models"
	"ssh-packet-capture/internal/packages"
	"ssh-packet-capture/internal/pcap"
)

// Client manages a single active SSH connection, offline installation, and live capture session.
type Client struct {
	mu      sync.Mutex
	sshConn *ssh.Client
	profile models.ServerProfile
	env     models.ServerEnvInfo

	captureMu      sync.Mutex
	capturing      bool
	captureSession *ssh.Session
	stopFlag       bool
}

func NewClient() *Client {
	return &Client{}
}

// Connect establishes an SSH connection and inspects the remote host environment.
func (c *Client) Connect(p models.ServerProfile, pkgMgr *packages.Manager) (models.ServerEnvInfo, error) {
	c.Disconnect()

	if p.Host == "" {
		return models.ServerEnvInfo{}, errors.New("服务器地址不能为空")
	}
	if p.Port <= 0 {
		p.Port = 22
	}
	if p.Username == "" {
		p.Username = "root"
	}

	authMethods, err := buildAuthMethods(p)
	if err != nil {
		return models.ServerEnvInfo{}, err
	}

	cfg := &ssh.ClientConfig{
		User:            p.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         12 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", strings.TrimSpace(p.Host), p.Port)
	conn, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return models.ServerEnvInfo{}, fmt.Errorf("SSH 连接失败 (%s): %w", addr, err)
	}

	c.mu.Lock()
	c.sshConn = conn
	c.profile = p
	c.mu.Unlock()

	env, err := c.RefreshEnv(pkgMgr)
	if err != nil {
		c.Disconnect()
		return models.ServerEnvInfo{}, err
	}
	return env, nil
}

// Disconnect closes any active capture and SSH connection.
func (c *Client) Disconnect() {
	c.StopCapture()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sshConn != nil {
		_ = c.sshConn.Close()
		c.sshConn = nil
	}
	c.env = models.ServerEnvInfo{Connected: false}
}

func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sshConn != nil
}

func (c *Client) CurrentEnv() models.ServerEnvInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.env
}

func (c *Client) CurrentProfile() models.ServerProfile {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.profile
}

// RefreshEnv inspects OS, architecture, tcpdump availability, privilege, and network interfaces.
func (c *Client) RefreshEnv(pkgMgr *packages.Manager) (models.ServerEnvInfo, error) {
	c.mu.Lock()
	conn := c.sshConn
	prof := c.profile
	c.mu.Unlock()

	if conn == nil {
		return models.ServerEnvInfo{}, errors.New("尚未连接 SSH 服务器")
	}

	script := `
echo "===OS_RELEASE==="
if [ -f /etc/os-release ]; then cat /etc/os-release; elif [ -f /etc/redhat-release ]; then echo "PRETTY_NAME=\"$(cat /etc/redhat-release)\""; fi
echo "===UNAME==="
uname -m
uname -r
echo "===UID==="
id -u
echo "===SUDO==="
if command -v sudo >/dev/null 2>&1; then echo "yes"; else echo "no"; fi
echo "===TCPDUMP==="
export PATH="$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin:$HOME/.local/bin"
TCPDUMP_BIN=$(command -v tcpdump 2>/dev/null || true)
echo "PATH=$TCPDUMP_BIN"
if [ -n "$TCPDUMP_BIN" ]; then "$TCPDUMP_BIN" --version 2>&1 | head -n 2; fi
echo "===IFACES==="
if command -v ip >/dev/null 2>&1; then
  ip -o -4 addr show 2>/dev/null | awk '{print $2 "|" $4}'
  echo "---LINKS---"
  ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | awk '{print $1}' | sed 's/@.*//'
elif command -v ifconfig >/dev/null 2>&1; then
  ifconfig -a 2>/dev/null | awk '/^[a-zA-Z0-9]/ {print $1}' | sed 's/://'
fi
`
	out, err := c.runCommand(script)
	if err != nil && strings.TrimSpace(out) == "" {
		return models.ServerEnvInfo{}, fmt.Errorf("检测远程系统环境失败: %w", err)
	}

	env := parseEnvOutput(out, prof)
	if pkgMgr != nil {
		if matched := pkgMgr.MatchPackage(env.NormalizedArch, env.OSID); matched != nil {
			env.MatchedPackageID = matched.ID
		}
	}

	c.mu.Lock()
	c.env = env
	c.mu.Unlock()
	return env, nil
}

// InstallTcpdumpOffline uploads and installs an offline tcpdump package onto the remote host.
func (c *Client) InstallTcpdumpOffline(
	pkg models.OfflinePackage,
	reader io.Reader,
	pkgMgr *packages.Manager,
	onProgress func(models.InstallProgress),
) (models.ServerEnvInfo, error) {
	c.mu.Lock()
	conn := c.sshConn
	prof := c.profile
	env := c.env
	c.mu.Unlock()

	if conn == nil {
		return models.ServerEnvInfo{}, errors.New("尚未连接 SSH 服务器")
	}

	report := func(step int, title, detail, status string, pct int) {
		if onProgress != nil {
			onProgress(models.InstallProgress{
				Step:       step,
				TotalSteps: 5,
				Title:      title,
				Detail:     detail,
				Status:     status,
				Percent:    pct,
			})
		}
	}

	report(1, "检测远程环境", fmt.Sprintf("目标系统: %s (%s)，权限: %s", env.OSName, env.Arch, privilegeLabel(env)), "running", 10)
	time.Sleep(150 * time.Millisecond)
	report(2, "准备离线安装包", fmt.Sprintf("已匹配 %s (%s, %.2f MB)", pkg.Name, pkg.Format, float64(pkg.Size)/1024.0/1024.0), "running", 25)

	remoteTmp := fmt.Sprintf("/tmp/netprobe_tcpdump_%d", time.Now().Unix())
	switch pkg.Format {
	case "rpm":
		remoteTmp += ".rpm"
	case "deb":
		remoteTmp += ".deb"
	case "tar.gz":
		remoteTmp += ".tar.gz"
	}

	report(3, "上传离线包到服务器", fmt.Sprintf("正在通过 SFTP 上传至 %s ...", remoteTmp), "running", 35)
	if err := c.uploadFile(conn, reader, pkg.Size, remoteTmp, func(pct int) {
		// map 0..100 upload progress into overall 35..75
		overall := 35 + (pct*40)/100
		report(3, "上传离线包到服务器", fmt.Sprintf("传输进度 %d%% (%s)", pct, remoteTmp), "running", overall)
	}); err != nil {
		report(3, "上传离线包失败", err.Error(), "error", 35)
		return env, fmt.Errorf("上传离线包失败: %w", err)
	}

	report(4, "执行离线安装与赋权", fmt.Sprintf("正在安装 %s 格式离线包...", pkg.Format), "running", 80)

	installCmd := buildInstallCommand(pkg.Format, remoteTmp, env.IsRoot, prof.UseSudo || env.CanSudo, prof.SudoPassword, prof.Password)
	out, err := c.runCommand(installCmd)
	if err != nil {
		msg := strings.TrimSpace(out)
		if msg == "" {
			msg = err.Error()
		}
		report(4, "离线安装失败", msg, "error", 80)
		return env, fmt.Errorf("离线安装执行失败: %s", msg)
	}

	report(5, "验证 tcpdump 可用性", "正在检查 tcpdump 版本与可执行权限...", "running", 92)
	newEnv, err := c.RefreshEnv(pkgMgr)
	if err != nil {
		report(5, "验证失败", err.Error(), "error", 92)
		return env, err
	}
	if !newEnv.HasTcpdump {
		report(5, "验证失败", "安装后仍未检测到 tcpdump 命令，请查看操作日志", "error", 95)
		return newEnv, errors.New("安装完成后未检测到 tcpdump 命令")
	}

	report(5, "离线安装完成", fmt.Sprintf("已就绪: %s (%s)", newEnv.TcpdumpPath, newEnv.TcpdumpVersion), "done", 100)
	return newEnv, nil
}

// StartCapture launches remote tcpdump -U -w - and streams packets via onPacket callback.
func (c *Client) StartCapture(
	cfg models.CaptureConfig,
	onHeader func(pcap.GlobalHeader),
	onPacket func(*pcap.RawPacket),
	onStderr func(string),
	onDone func(error),
) (string, error) {
	c.mu.Lock()
	conn := c.sshConn
	env := c.env
	prof := c.profile
	c.mu.Unlock()

	if conn == nil {
		return "", errors.New("尚未连接 SSH 服务器")
	}
	if !env.HasTcpdump {
		return "", errors.New("远程服务器未安装 tcpdump，请先执行自动离线安装")
	}

	c.captureMu.Lock()
	if c.capturing {
		c.captureMu.Unlock()
		return "", errors.New("当前已有正在进行的抓包任务")
	}
	session, err := conn.NewSession()
	if err != nil {
		c.captureMu.Unlock()
		return "", fmt.Errorf("创建 SSH 会话失败: %w", err)
	}
	c.capturing = true
	c.captureSession = session
	c.stopFlag = false
	c.captureMu.Unlock()

	cmdStr, displayCmd := buildTcpdumpCommand(cfg, env, prof)

	stdout, err := session.StdoutPipe()
	if err != nil {
		c.resetCapture()
		_ = session.Close()
		return "", err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		c.resetCapture()
		_ = session.Close()
		return "", err
	}

	if err := session.Start(cmdStr); err != nil {
		c.resetCapture()
		_ = session.Close()
		return "", fmt.Errorf("启动远程 tcpdump 失败: %w", err)
	}

	// Capture stderr diagnostics in background
	var stderrBuf bytes.Buffer
	var stderrMu sync.Mutex
	go func() {
		buf := make([]byte, 2048)
		for {
			n, rerr := stderr.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				stderrMu.Lock()
				stderrBuf.WriteString(chunk)
				stderrMu.Unlock()
				if onStderr != nil {
					for _, line := range strings.Split(strings.TrimSpace(chunk), "\n") {
						line = strings.TrimSpace(line)
						if line != "" {
							onStderr(line)
						}
					}
				}
			}
			if rerr != nil {
				break
			}
		}
	}()

	// Stream PCAP packets in background
	go func() {
		defer func() {
			_ = session.Close()
			c.resetCapture()
		}()

		sr, err := pcap.NewStreamReader(stdout)
		if err != nil {
			c.captureMu.Lock()
			stopped := c.stopFlag
			c.captureMu.Unlock()
			if stopped {
				if onDone != nil {
					onDone(nil)
				}
				return
			}
			stderrMu.Lock()
			errMsg := strings.TrimSpace(stderrBuf.String())
			stderrMu.Unlock()
			if errMsg != "" {
				err = fmt.Errorf("tcpdump 启动异常: %s", errMsg)
			}
			if onDone != nil {
				onDone(err)
			}
			return
		}

		if onHeader != nil {
			onHeader(sr.Header)
		}

		seq := 0
		for {
			seq++
			pkt, rerr := sr.ReadNext(seq)
			if rerr != nil {
				c.captureMu.Lock()
				stopped := c.stopFlag
				c.captureMu.Unlock()
				if stopped || errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
					if onDone != nil {
						onDone(nil)
					}
				} else {
					if onDone != nil {
						onDone(rerr)
					}
				}
				return
			}
			if onPacket != nil {
				onPacket(pkt)
			}
		}
	}()

	return displayCmd, nil
}

// StopCapture terminates the running tcpdump SSH session cleanly.
func (c *Client) StopCapture() {
	c.captureMu.Lock()
	c.stopFlag = true
	sess := c.captureSession
	c.captureMu.Unlock()

	if sess != nil {
		_ = sess.Signal(ssh.SIGINT)
		_ = sess.Close()
	}
}

func (c *Client) resetCapture() {
	c.captureMu.Lock()
	c.capturing = false
	c.captureSession = nil
	c.captureMu.Unlock()
}

func (c *Client) runCommand(cmd string) (string, error) {
	c.mu.Lock()
	conn := c.sshConn
	c.mu.Unlock()
	if conn == nil {
		return "", errors.New("SSH 未连接")
	}

	sess, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	var buf bytes.Buffer
	sess.Stdout = &buf
	sess.Stderr = &buf
	err = sess.Run(cmd)
	return buf.String(), err
}

func (c *Client) uploadFile(conn *ssh.Client, reader io.Reader, totalSize int64, remotePath string, onPct func(int)) error {
	// Primary: SFTP upload
	sftpClient, err := sftp.NewClient(conn)
	if err == nil {
		defer sftpClient.Close()
		rf, err := sftpClient.Create(remotePath)
		if err == nil {
			defer rf.Close()
			buf := make([]byte, 32*1024)
			var written int64
			lastPct := -1
			for {
				n, rerr := reader.Read(buf)
				if n > 0 {
					wn, werr := rf.Write(buf[:n])
					if werr != nil {
						return werr
					}
					written += int64(wn)
					if totalSize > 0 && onPct != nil {
						pct := int((written * 100) / totalSize)
						if pct > 100 {
							pct = 100
						}
						if pct != lastPct {
							lastPct = pct
							onPct(pct)
						}
					}
				}
				if errors.Is(rerr, io.EOF) {
					break
				}
				if rerr != nil {
					return rerr
				}
			}
			return nil
		}
	}

	// Fallback: pipe base64 over SSH exec (for embedded Linux without sftp-server)
	allBytes, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	sess, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	encoded := base64.StdEncoding.EncodeToString(allBytes)
	sess.Stdin = strings.NewReader(encoded)
	if onPct != nil {
		onPct(60)
	}
	if out, err := sess.CombinedOutput(fmt.Sprintf("base64 -d > %s", shellQuote(remotePath))); err != nil {
		return fmt.Errorf("SSH 传输回退失败: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	if onPct != nil {
		onPct(100)
	}
	return nil
}

func buildAuthMethods(p models.ServerProfile) ([]ssh.AuthMethod, error) {
	if p.AuthType == "key" {
		if p.PrivateKeyPath == "" {
			return nil, errors.New("请选择 SSH 私钥文件")
		}
		keyBytes, err := os.ReadFile(p.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("读取私钥文件失败: %w", err)
		}
		var signer ssh.Signer
		if p.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(p.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("解析 SSH 私钥失败: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}

	if p.Password == "" {
		return nil, errors.New("请输入 SSH 登录密码")
	}
	return []ssh.AuthMethod{
		ssh.Password(p.Password),
		ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				answers[i] = p.Password
			}
			return answers, nil
		}),
	}, nil
}

func parseEnvOutput(out string, prof models.ServerProfile) models.ServerEnvInfo {
	env := models.ServerEnvInfo{
		Connected:   true,
		ProfileID:   prof.ID,
		ProfileName: prof.Name,
		Host:        prof.Host,
		Port:        prof.Port,
		Username:    prof.Username,
		OSName:      "Linux",
		OSID:        "linux",
		Interfaces:  []models.NetInterface{},
	}

	sections := splitSections(out)

	// Parse OS release
	for _, line := range strings.Split(sections["OS_RELEASE"], "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			env.OSName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"'")
		} else if strings.HasPrefix(line, "ID=") {
			env.OSID = strings.ToLower(strings.Trim(strings.TrimPrefix(line, "ID="), "\"'"))
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			env.OSVersion = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"'")
		}
	}

	// Parse uname
	unameLines := nonEmptyLines(sections["UNAME"])
	if len(unameLines) >= 1 {
		env.Arch = unameLines[0]
		env.NormalizedArch = packages.NormalizeArch(env.Arch)
	}
	if len(unameLines) >= 2 {
		env.Kernel = unameLines[1]
	}

	// Parse UID & sudo
	uid := strings.TrimSpace(sections["UID"])
	env.IsRoot = uid == "0"
	env.CanSudo = strings.TrimSpace(sections["SUDO"]) == "yes"

	// Parse tcpdump
	for _, line := range nonEmptyLines(sections["TCPDUMP"]) {
		if strings.HasPrefix(line, "PATH=") {
			p := strings.TrimSpace(strings.TrimPrefix(line, "PATH="))
			if p != "" {
				env.HasTcpdump = true
				env.TcpdumpPath = p
			}
		} else if env.TcpdumpVersion == "" && strings.Contains(strings.ToLower(line), "tcpdump") {
			env.TcpdumpVersion = line
		}
	}

	// Parse network interfaces
	ipMap := map[string]string{}
	ifParts := strings.Split(sections["IFACES"], "---LINKS---")
	if len(ifParts) >= 1 {
		for _, line := range nonEmptyLines(ifParts[0]) {
			if strings.Contains(line, "|") {
				kv := strings.SplitN(line, "|", 2)
				name := strings.TrimSpace(kv[0])
				ip := strings.TrimSpace(kv[1])
				if _, exists := ipMap[name]; !exists {
					ipMap[name] = ip
				}
			}
		}
	}

	env.Interfaces = append(env.Interfaces, models.NetInterface{
		Name:        "any",
		IP:          "全部网卡",
		State:       "UP",
		Description: "监听所有网络接口 (Linux SLL)",
	})

	seen := map[string]bool{"any": true}
	var linkLines []string
	if len(ifParts) >= 2 {
		linkLines = nonEmptyLines(ifParts[1])
	} else {
		linkLines = nonEmptyLines(sections["IFACES"])
	}
	for _, raw := range linkLines {
		name := strings.TrimSpace(strings.Split(raw, "|")[0])
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		ip := ipMap[name]
		if ip == "" {
			ip = "-"
		}
		env.Interfaces = append(env.Interfaces, models.NetInterface{
			Name:  name,
			IP:    ip,
			State: "UP",
		})
	}

	return env
}

func buildInstallCommand(format, remoteTmp string, isRoot, useSudo bool, sudoPass, sshPass string) string {
	pw := sudoPass
	if pw == "" {
		pw = sshPass
	}
	runPriv := func(inner string) string {
		if isRoot {
			return inner
		}
		if useSudo && pw != "" {
			return fmt.Sprintf("printf '%%s\\n' %s | sudo -S sh -c %s", shellQuote(pw), shellQuote(inner))
		}
		if useSudo {
			return fmt.Sprintf("sudo sh -c %s", shellQuote(inner))
		}
		return inner
	}

	var core string
	switch format {
	case "rpm":
		core = fmt.Sprintf("rpm -Uvh --nodeps --force %s && rm -f %s", shellQuote(remoteTmp), shellQuote(remoteTmp))
		return runPriv(core)
	case "deb":
		core = fmt.Sprintf("dpkg -i %s && rm -f %s", shellQuote(remoteTmp), shellQuote(remoteTmp))
		return runPriv(core)
	case "tar.gz":
		core = fmt.Sprintf(
			"TMPD=$(mktemp -d) && tar -xzf %s -C \"$TMPD\" && BIN=$(find \"$TMPD\" -type f -name tcpdump | head -n 1) && [ -n \"$BIN\" ] && install -m 755 \"$BIN\" /usr/local/bin/tcpdump && rm -rf \"$TMPD\" %s",
			shellQuote(remoteTmp), shellQuote(remoteTmp),
		)
		return runPriv(core)
	default: // static-bin
		if isRoot || useSudo {
			core = fmt.Sprintf("mkdir -p /usr/local/bin && mv %s /usr/local/bin/tcpdump && chmod 755 /usr/local/bin/tcpdump", shellQuote(remoteTmp))
			return runPriv(core)
		}
		return fmt.Sprintf("mkdir -p \"$HOME/.local/bin\" && mv %s \"$HOME/.local/bin/tcpdump\" && chmod 755 \"$HOME/.local/bin/tcpdump\"", shellQuote(remoteTmp))
	}
}

func buildTcpdumpCommand(cfg models.CaptureConfig, env models.ServerEnvInfo, prof models.ServerProfile) (execCmd string, displayCmd string) {
	iface := strings.TrimSpace(cfg.Interface)
	if iface == "" {
		iface = "any"
	}
	bin := env.TcpdumpPath
	if bin == "" {
		bin = "tcpdump"
	}

	args := []string{shellQuote(bin), "-i", shellQuote(iface), "-U", "-n"}
	if cfg.Snaplen > 0 {
		args = append(args, "-s", fmt.Sprintf("%d", cfg.Snaplen))
	} else {
		args = append(args, "-s", "0")
	}
	if !cfg.Promiscuous {
		args = append(args, "-p")
	}
	if cfg.MaxPackets > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", cfg.MaxPackets))
	}
	args = append(args, "-w", "-")

	// Combine SrcIP, DstIP, user BPF filter, and optional SSH traffic exclusion
	var filterParts []string
	if srcIP := strings.TrimSpace(cfg.SrcIP); srcIP != "" {
		filterParts = append(filterParts, fmt.Sprintf("src host %s", srcIP))
	}
	if dstIP := strings.TrimSpace(cfg.DstIP); dstIP != "" {
		filterParts = append(filterParts, fmt.Sprintf("dst host %s", dstIP))
	}
	if userFilter := strings.TrimSpace(cfg.Filter); userFilter != "" {
		filterParts = append(filterParts, fmt.Sprintf("(%s)", userFilter))
	}
	if cfg.ExcludeSSH {
		sshPort := prof.Port
		if sshPort <= 0 {
			sshPort = 22
		}
		filterParts = append(filterParts, fmt.Sprintf("not port %d", sshPort))
	}

	if len(filterParts) > 0 {
		finalFilter := strings.Join(filterParts, " and ")
		args = append(args, shellQuote(finalFilter))
	}

	baseCmd := strings.Join(args, " ")
	displayCmd = baseCmd

	if !env.IsRoot && (prof.UseSudo || env.CanSudo) {
		pw := prof.SudoPassword
		if pw == "" {
			pw = prof.Password
		}
		if pw != "" {
			execCmd = fmt.Sprintf("printf '%%s\\n' %s | sudo -S -p '' %s", shellQuote(pw), baseCmd)
			displayCmd = "sudo " + baseCmd
			return execCmd, displayCmd
		}
		execCmd = "sudo " + baseCmd
		displayCmd = execCmd
		return execCmd, displayCmd
	}

	return baseCmd, displayCmd
}

func splitSections(s string) map[string]string {
	out := map[string]string{}
	cur := ""
	var buf strings.Builder
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "===") && strings.HasSuffix(trimmed, "===") && len(trimmed) > 6 {
			if cur != "" {
				out[cur] = buf.String()
			}
			cur = strings.Trim(trimmed, "=")
			buf.Reset()
			continue
		}
		if cur != "" {
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}
	if cur != "" {
		out[cur] = buf.String()
	}
	return out
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func privilegeLabel(env models.ServerEnvInfo) string {
	if env.IsRoot {
		return "root"
	}
	if env.CanSudo {
		return "普通用户 (支持 sudo)"
	}
	return "普通用户"
}

// TestTCPReachable performs a quick TCP dial check (optional helper).
func TestTCPReachable(host string, port int) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}
