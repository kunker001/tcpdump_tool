import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Download,
  FileDown,
  Filter,
  Play,
  RefreshCw,
  Search,
  Square,
  Trash2,
} from 'lucide-react';
import {
  CaptureConfig,
  CaptureStats,
  PacketDetail,
  PacketSummary,
  ServerEnvInfo,
} from '../types';
import { EmptyState } from './EmptyState';

interface CaptureWorkspaceProps {
  env: ServerEnvInfo;
  packets: PacketSummary[];
  stats: CaptureStats;
  selectedNo: number | null;
  packetDetail: PacketDetail | null;
  onStartCapture: (cfg: CaptureConfig) => void;
  onStopCapture: () => void;
  onClearPackets: () => void;
  onExportPcap: () => void;
  onSelectPacket: (no: number) => void;
  onOpenInstallModal: () => void;
  onGoToServers: () => void;
  onRefreshEnv: () => void;
}

const FILTER_PRESETS = [
  { label: '全部流量', value: '' },
  { label: 'SIP (5060/5061)', value: 'port 5060 or port 5061' },
  { label: 'HTTP / HTTPS', value: 'tcp port 80 or tcp port 443' },
  { label: 'DNS', value: 'port 53' },
  { label: 'ICMP (Ping)', value: 'icmp' },
  { label: 'TCP SYN', value: 'tcp[tcpflags] & tcp-syn != 0' },
  { label: 'ARP', value: 'arp' },
];

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function protocolTagClass(proto: string): string {
  switch (proto) {
    case 'SIP':
    case 'HTTP':
    case 'TLS':
      return 'tag tag-blue';
    case 'DNS':
    case 'UDP':
      return 'tag tag-green';
    case 'ICMP':
    case 'ICMPv6':
    case 'ARP':
      return 'tag tag-amber';
    case 'SSH':
      return 'tag';
    default:
      return 'tag';
  }
}

export const CaptureWorkspace: React.FC<CaptureWorkspaceProps> = ({
  env,
  packets,
  stats,
  selectedNo,
  packetDetail,
  onStartCapture,
  onStopCapture,
  onClearPackets,
  onExportPcap,
  onSelectPacket,
  onOpenInstallModal,
  onGoToServers,
  onRefreshEnv,
}) => {
  const [iface, setIface] = useState('any');
  const [srcIp, setSrcIp] = useState('');
  const [dstIp, setDstIp] = useState('');
  const [filter, setFilter] = useState('');
  const [maxPackets, setMaxPackets] = useState(0);
  const [excludeSsh, setExcludeSsh] = useState(true);
  const [displaySearch, setDisplaySearch] = useState('');
  const [expandedLayers, setExpandedLayers] = useState<Record<number, boolean>>({
    0: true,
    1: false,
    2: true,
    3: true,
    4: true,
  });

  const filteredPackets = useMemo(() => {
    const q = displaySearch.trim().toLowerCase();
    if (!q) return packets;
    return packets.filter(
      (p) =>
        p.srcAddr.toLowerCase().includes(q) ||
        p.dstAddr.toLowerCase().includes(q) ||
        p.protocol.toLowerCase().includes(q) ||
        p.info.toLowerCase().includes(q) ||
        String(p.no) === q
    );
  }, [packets, displaySearch]);

  const handleStart = () => {
    onStartCapture({
      interface: iface || 'any',
      srcIp: srcIp.trim(),
      dstIp: dstIp.trim(),
      filter: filter.trim(),
      maxPackets: Number(maxPackets) || 0,
      snaplen: 0,
      excludeSsh,
      promiscuous: true,
    });
  };

  const toggleLayer = (idx: number) => {
    setExpandedLayers((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, height: '100%', minHeight: 0 }}>
      {/* Missing tcpdump warning banner */}
      {env.connected && !env.hasTcpdump && (
        <div className="banner banner-warn">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <AlertTriangle size={16} color="#D97706" style={{ flexShrink: 0 }} />
            <div>
              <strong>远程服务器未检测到 tcpdump 命令</strong>
              <span style={{ marginLeft: 8, color: '#78350F' }}>
                已识别系统：{env.osName} ({env.arch})，可使用内置静态离线包一键部署。
              </span>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            <button className="btn btn-secondary btn-sm" onClick={onRefreshEnv}>
              <RefreshCw size={13} />
              重新检测
            </button>
            <button className="btn btn-primary btn-sm" onClick={onOpenInstallModal}>
              <Download size={13} />
              自动离线安装
            </button>
          </div>
        </div>
      )}

      {/* Top Capture Toolbar Panel */}
      <div className="panel capture-toolbar">
        <div className="toolbar-row">
          <div className="field-inline">
            <span className="field-label">监听网卡</span>
            <select
              className="select"
              style={{ width: 175 }}
              value={iface}
              disabled={!env.connected || stats.running}
              onChange={(e) => setIface(e.target.value)}
            >
              {(env.interfaces && env.interfaces.length > 0
                ? env.interfaces
                : [{ name: 'any', ip: '全部网卡', state: 'UP', description: '' }]
              ).map((ni) => (
                <option key={ni.name} value={ni.name}>
                  {ni.name} {ni.ip && ni.ip !== '-' ? `(${ni.ip})` : ''}
                </option>
              ))}
            </select>
          </div>

          <div className="field-inline">
            <span className="field-label">源 IP</span>
            <input
              className="input input-mono"
              style={{ width: 138 }}
              placeholder="如 192.168.1.10"
              value={srcIp}
              disabled={!env.connected || stats.running}
              onChange={(e) => setSrcIp(e.target.value)}
            />
          </div>

          <div className="field-inline">
            <span className="field-label">目的 IP</span>
            <input
              className="input input-mono"
              style={{ width: 138 }}
              placeholder="如 10.0.0.5"
              value={dstIp}
              disabled={!env.connected || stats.running}
              onChange={(e) => setDstIp(e.target.value)}
            />
          </div>

          <div className="field-inline" style={{ flex: 1, minWidth: 200 }}>
            <Filter size={14} color="#64748B" />
            <input
              className="input input-mono"
              style={{ width: '100%' }}
              placeholder="BPF 过滤器，例如: port 5060 or tcp port 80"
              value={filter}
              disabled={!env.connected || stats.running}
              onChange={(e) => setFilter(e.target.value)}
            />
          </div>

          <div className="field-inline">
            <span className="field-label">上限</span>
            <input
              type="number"
              min={0}
              max={20000}
              className="input"
              style={{ width: 78 }}
              placeholder="不限"
              title="最大抓包数量 (0 表示不限制)"
              value={maxPackets === 0 ? '' : maxPackets}
              disabled={!env.connected || stats.running}
              onChange={(e) => setMaxPackets(parseInt(e.target.value, 10) || 0)}
            />
          </div>

          {!stats.running ? (
            <button
              className="btn btn-primary"
              disabled={!env.connected || !env.hasTcpdump}
              onClick={handleStart}
            >
              <Play size={14} />
              开始抓包
            </button>
          ) : (
            <button className="btn btn-danger" onClick={onStopCapture}>
              <Square size={13} />
              停止抓包
            </button>
          )}

          <button
            className="btn btn-secondary"
            disabled={packets.length === 0}
            onClick={onClearPackets}
            title="清空当前列表"
          >
            <Trash2 size={14} />
            清空
          </button>

          <button
            className="btn btn-secondary"
            disabled={packets.length === 0}
            onClick={onExportPcap}
            title="导出为 Wireshark 标准 .pcap 文件"
          >
            <FileDown size={14} />
            导出 PCAP
          </button>
        </div>

        <div className="toolbar-row" style={{ justifyContent: 'space-between' }}>
          <div className="preset-pills">
            <span className="field-label">快捷过滤：</span>
            {FILTER_PRESETS.map((p) => (
              <button
                key={p.label}
                className={`preset-pill ${filter.trim() === p.value ? 'active' : ''}`}
                disabled={!env.connected || stats.running}
                onClick={() => setFilter(p.value)}
              >
                {p.label}
              </button>
            ))}
          </div>

          <label className="checkbox-label" title="自动附加 not port <SSH端口>，防止抓取当前 SSH 传输流量引起循环">
            <input
              type="checkbox"
              checked={excludeSsh}
              disabled={stats.running}
              onChange={(e) => setExcludeSsh(e.target.checked)}
            />
            自动排除当前 SSH 流量
          </label>
        </div>
      </div>

      {/* Main Packet Table Panel */}
      <div
        className="panel"
        style={{
          flex: 1,
          minHeight: 0,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        {/* Metrics + Display Search Strip */}
        <div className="metrics-strip">
          <div className="metrics-group">
            <div className="metric-item">
              <span>已捕获</span>
              <span className="metric-value">{stats.totalPackets}</span>
              <span>包</span>
            </div>
            <div className="metric-item">
              <span>总流量</span>
              <span className="metric-value">{formatBytes(stats.totalBytes)}</span>
            </div>
            <div className="metric-item">
              <span>速率</span>
              <span className="metric-value">{stats.packetsPerSec.toFixed(1)}</span>
              <span>pkt/s</span>
            </div>
            <div className="metric-item">
              <span>耗时</span>
              <span className="metric-value">{stats.elapsedSec.toFixed(1)}s</span>
            </div>
            {Object.entries(stats.protocols || {})
              .sort((a, b) => b[1] - a[1])
              .slice(0, 5)
              .map(([proto, count]) => (
                <span key={proto} className={protocolTagClass(proto)}>
                  {proto} {count}
                </span>
              ))}
          </div>

          <div style={{ position: 'relative', width: 220 }}>
            <Search
              size={13}
              color="#94A3B8"
              style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)' }}
            />
            <input
              className="input"
              style={{ width: '100%', height: 28, paddingLeft: 28, fontSize: 12 }}
              placeholder="列表筛选 IP / 协议 / 摘要..."
              value={displaySearch}
              onChange={(e) => setDisplaySearch(e.target.value)}
            />
          </div>
        </div>

        {/* Table Body or Empty States */}
        {!env.connected ? (
          <EmptyState
            variant="disconnected"
            title="尚未连接目标服务器"
            description="请先在「服务器管理」中添加并连接一台 Linux 服务器，系统将自动检测架构与 tcpdump 环境。"
            action={
              <button className="btn btn-primary" onClick={onGoToServers}>
                前往连接服务器
              </button>
            }
          />
        ) : filteredPackets.length === 0 ? (
          <EmptyState
            variant="ready"
            title={stats.running ? '正在监听网络流量...' : '已就绪，等待开始抓包'}
            description={
              stats.running
                ? `已启动远程监听 (${stats.command || 'tcpdump'})，收到匹配数据包后将实时显示于此。`
                : '选择监听网卡与过滤条件，点击右上角「开始抓包」即可实时解析并录制 PCAP 报文。'
            }
          />
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 64 }}>序号</th>
                  <th style={{ width: 120 }}>时间</th>
                  <th style={{ width: 175 }}>源地址</th>
                  <th style={{ width: 175 }}>目的地址</th>
                  <th style={{ width: 78 }}>协议</th>
                  <th style={{ width: 68 }}>长度</th>
                  <th>摘要信息</th>
                </tr>
              </thead>
              <tbody>
                {filteredPackets.map((p) => (
                  <tr
                    key={p.no}
                    className={selectedNo === p.no ? 'selected' : ''}
                    onClick={() => onSelectPacket(p.no)}
                  >
                    <td className="mono">{p.no}</td>
                    <td className="mono">{p.timestamp}</td>
                    <td className="mono" title={p.srcAddr}>
                      {p.srcAddr}
                    </td>
                    <td className="mono" title={p.dstAddr}>
                      {p.dstAddr}
                    </td>
                    <td>
                      <span className={protocolTagClass(p.protocol)}>{p.protocol}</span>
                    </td>
                    <td className="mono">{p.length}</td>
                    <td title={p.info}>{p.info}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Bottom Packet Dissection & Hex Dump Panel */}
      {packetDetail && (
        <div className="panel detail-panel">
          <div className="detail-pane">
            <div className="detail-pane-title">
              <span>协议层级解析 — 帧 #{packetDetail.summary.no}</span>
              <span className="mono" style={{ fontWeight: 400 }}>
                {packetDetail.rawLen} bytes
              </span>
            </div>
            <div className="detail-pane-body">
              {packetDetail.layers.map((layer, idx) => {
                const open = expandedLayers[idx] ?? true;
                return (
                  <div key={idx} className="layer-block">
                    <div className="layer-header" onClick={() => toggleLayer(idx)}>
                      {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                      <span>{layer.name}</span>
                      <span className="layer-summary">{layer.summary}</span>
                    </div>
                    {open && (
                      <div className="layer-fields">
                        {layer.fields.map((f, fIdx) => (
                          <div key={fIdx} className="layer-field">
                            <span className="layer-field-key">{f.key}</span>
                            <span className="layer-field-val">{f.value}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          <div className="detail-pane">
            <div className="detail-pane-title">
              <span>十六进制 / ASCII 原始报文</span>
              <span className="mono" style={{ fontWeight: 400 }}>
                {packetDetail.summary.protocol}
              </span>
            </div>
            <div className="detail-pane-body">
              <div className="hex-table">
                {packetDetail.hexDump.map((line) => (
                  <div key={line.offset} className="hex-row">
                    <span className="hex-offset">{line.offset}</span>
                    <span className="hex-bytes">{line.hex}</span>
                    <span className="hex-ascii">{line.ascii}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
