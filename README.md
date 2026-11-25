# NetProbe — SSH 远程抓包工具

基于 **Go + Wails + React (TypeScript)** 开发的 Windows 桌面端 SSH 远程网络抓包工具。支持通过 SSH 连接 Linux 服务器直接调用 `tcpdump` 实时流式抓包、协议解析与 Wireshark `.pcap` 导出；当目标服务器未安装 `tcpdump` 时，可根据系统架构与发行版自动离线安装。

## 核心特性

- **SSH 远程连接与环境自检**：支持密码 / 私钥认证与 `sudo` 提权；连接后自动识别操作系统、CPU 架构、内核版本、网卡列表与 `tcpdump` 状态。
- **自动离线安装 `tcpdump`**：
  - 内置 4 个无依赖静态编译版 Linux `tcpdump 4.9.3`（`x86_64` / `aarch64` / `armhf` / `x86`），通过 `//go:embed` 打包进单个可执行文件。
  - 自动按架构匹配并通过 SFTP 上传安装（无 SFTP 环境自动回退 SSH 传输），配备 5 步可视化进度条。
  - 支持在「离线安装库」中导入自定义 `.rpm` / `.deb` / `.tar.gz` / 静态二进制包。
- **实时流式抓包与协议解析**：
  - 通过 `tcpdump -U -n -s 0 -w -` 实时拉取 libpcap 数据流，不占用远程服务器磁盘空间。
  - 支持独立的 **源 IP**、**目的 IP**、**BPF 过滤器** 输入框，以及 `SIP (5060/5061)`、`HTTP/HTTPS`、`DNS`、`ICMP`、`TCP SYN`、`ARP` 快捷预设；默认自动排除当前 SSH 连接流量。
  - 纯 Go 解析 Ethernet / Linux SLL / VLAN / ARP / IPv4 / IPv6 / TCP / UDP / ICMP / DNS / HTTP / TLS / SSH / **SIP** 协议层级与十六进制 / ASCII 原始报文。
  - 支持一键导出标准 Wireshark `.pcap` 文件。
- **企业级桌面界面**：浅灰蓝底色 + 白色面板 + 明亮蓝色强调色，紧凑表格、线性图标与柔和空状态插画，默认采用 Microsoft YaHei 字体。

## 快速开始

### 环境要求
- Go 1.21+
- Node.js 18+
- Wails v2 CLI (`go install github.com/wailsapp/wails/v2/cmd/wails@latest`)

### 本地开发与打包
```powershell
# 开发模式（热重载）
wails dev

# 编译 Windows 生产版可执行文件 (输出至 build/bin/ssh-packet-capture.exe)
wails build
```

### 运行测试
```powershell
go test -v ./...
```
