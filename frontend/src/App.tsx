import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  CheckCircle2,
  Download,
  Info,
  Package,
  ScrollText,
  Server,
  Unplug,
  XCircle,
} from 'lucide-react';
import * as AppAPI from '../wailsjs/go/main/App';
import { EventsOff, EventsOn } from '../wailsjs/runtime/runtime';
import {
  CaptureConfig,
  CaptureStats,
  InstallProgress,
  LogEntry,
  NavTab,
  OfflinePackage,
  PacketDetail,
  PacketSummary,
  ServerEnvInfo,
  ServerProfile,
} from './types';
import { CaptureWorkspace } from './components/CaptureWorkspace';
import { ServerManager } from './components/ServerManager';
import { OfflineRepo } from './components/OfflineRepo';
import { ActivityLogs } from './components/ActivityLogs';
import { InstallModal } from './components/InstallModal';

const EMPTY_ENV: ServerEnvInfo = {
  connected: false,
  profileId: '',
  profileName: '',
  host: '',
  port: 22,
  username: '',
  osName: '',
  osId: '',
  osVersion: '',
  kernel: '',
  arch: '',
  normalizedArch: '',
  hasTcpdump: false,
  tcpdumpPath: '',
  tcpdumpVersion: '',
  isRoot: false,
  canSudo: false,
  interfaces: [],
  matchedPackageId: '',
};

const EMPTY_STATS: CaptureStats = {
  running: false,
  totalPackets: 0,
  totalBytes: 0,
  elapsedSec: 0,
  packetsPerSec: 0,
  bytesPerSec: 0,
  protocols: {},
  command: '',
};

interface ToastItem {
  id: number;
  type: 'success' | 'error' | 'info';
  text: string;
}

export function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('capture');
  const [profiles, setProfiles] = useState<ServerProfile[]>([]);
  const [packages, setPackages] = useState<OfflinePackage[]>([]);
  const [env, setEnv] = useState<ServerEnvInfo>(EMPTY_ENV);
  const [connectingId, setConnectingId] = useState<string | null>(null);

  const [packets, setPackets] = useState<PacketSummary[]>([]);
  const [stats, setStats] = useState<CaptureStats>(EMPTY_STATS);
  const [selectedNo, setSelectedNo] = useState<number | null>(null);
  const [packetDetail, setPacketDetail] = useState<PacketDetail | null>(null);

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  // Offline install modal state
  const [installOpen, setInstallOpen] = useState(false);
  const [installInitPkgId, setInstallInitPkgId] = useState<string | undefined>(undefined);
  const [installing, setInstalling] = useState(false);
  const [installProgress, setInstallProgress] = useState<InstallProgress | null>(null);

  const pushToast = useCallback((type: ToastItem['type'], text: string) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev.slice(-3), { id, type, text }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3800);
  }, []);

  // Load initial data
  const refreshAll = useCallback(async () => {
    try {
      const [pList, pkgList, logList, curEnv] = await Promise.all([
        AppAPI.ListProfiles(),
        AppAPI.ListOfflinePackages(),
        AppAPI.GetLogs(),
        AppAPI.GetServerEnv(),
      ]);
      setProfiles((pList || []) as ServerProfile[]);
      setPackages((pkgList || []) as OfflinePackage[]);
      setLogs((logList || []) as LogEntry[]);
      if (curEnv) setEnv(curEnv as ServerEnvInfo);
    } catch (e) {
      console.error(e);
    }
  }, []);

  useEffect(() => {
    refreshAll();

    EventsOn('capture:packets', (batch: PacketSummary[]) => {
      if (!batch || batch.length === 0) return;
      setPackets((prev) => {
        const next = prev.concat(batch);
        return next.length > 20000 ? next.slice(next.length - 20000) : next;
      });
    });

    EventsOn('capture:stats', (st: CaptureStats) => {
      if (st) setStats(st);
    });

    EventsOn('capture:stopped', (st: CaptureStats) => {
      if (st) setStats({ ...st, running: false });
    });

    EventsOn('capture:error', (msg: string) => {
      pushToast('error', msg);
    });

    EventsOn('install:progress', (prog: InstallProgress) => {
      setInstallProgress(prog);
    });

    EventsOn('log:entry', (entry: LogEntry) => {
      if (!entry) return;
      setLogs((prev) => [...prev.slice(-499), entry]);
    });

    return () => {
      EventsOff(
        'capture:packets',
        'capture:stats',
        'capture:stopped',
        'capture:error',
        'install:progress',
        'log:entry'
      );
    };
  }, [refreshAll, pushToast]);

  // --- Handlers ---

  const handleSaveProfile = async (p: ServerProfile) => {
    await AppAPI.SaveProfile(p as any);
    const list = await AppAPI.ListProfiles();
    setProfiles((list || []) as ServerProfile[]);
    pushToast('success', `已保存服务器：${p.name}`);
  };

  const handleDeleteProfile = async (id: string) => {
    await AppAPI.DeleteProfile(id);
    const list = await AppAPI.ListProfiles();
    setProfiles((list || []) as ServerProfile[]);
    pushToast('info', '已删除服务器配置');
  };

  const handleConnect = async (p: ServerProfile) => {
    setConnectingId(p.id);
    try {
      const res = (await AppAPI.ConnectServer(p as any)) as ServerEnvInfo;
      setEnv(res);
      const list = await AppAPI.ListProfiles();
      setProfiles((list || []) as ServerProfile[]);
      if (res.hasTcpdump) {
        pushToast('success', `已连接 ${res.host} (${res.arch})，tcpdump 已就绪`);
        setActiveTab('capture');
      } else {
        pushToast('info', `已连接 ${res.host}，未检测到 tcpdump，可一键离线安装`);
        setActiveTab('capture');
      }
    } catch (err: any) {
      pushToast('error', String(err));
    } finally {
      setConnectingId(null);
    }
  };

  const handleDisconnect = async () => {
    await AppAPI.DisconnectServer();
    setEnv(EMPTY_ENV);
    setStats((prev) => ({ ...prev, running: false }));
    pushToast('info', '已断开 SSH 连接');
  };

  const handleRefreshEnv = async () => {
    try {
      const res = (await AppAPI.RefreshServerEnv()) as ServerEnvInfo;
      setEnv(res);
      pushToast('info', res.hasTcpdump ? '检测到 tcpdump 已就绪' : '仍未检测到 tcpdump');
    } catch (err: any) {
      pushToast('error', String(err));
    }
  };

  const handleStartCapture = async (cfg: CaptureConfig) => {
    setPackets([]);
    setSelectedNo(null);
    setPacketDetail(null);
    try {
      const cmd = await AppAPI.StartCapture(cfg as any);
      setStats({ ...EMPTY_STATS, running: true, command: cmd });
      pushToast('success', '远程抓包已启动');
    } catch (err: any) {
      pushToast('error', String(err));
    }
  };

  const handleStopCapture = async () => {
    await AppAPI.StopCapture();
  };

  const handleClearPackets = async () => {
    await AppAPI.ClearPackets();
    setPackets([]);
    setSelectedNo(null);
    setPacketDetail(null);
    setStats((prev) => ({ ...EMPTY_STATS, running: prev.running, command: prev.command }));
  };

  const handleExportPcap = async () => {
    try {
      const saved = await AppAPI.ExportPcap();
      if (saved) {
        pushToast('success', `已导出 PCAP 至：${saved}`);
      }
    } catch (err: any) {
      pushToast('error', String(err));
    }
  };

  const handleSelectPacket = async (no: number) => {
    setSelectedNo(no);
    try {
      const detail = (await AppAPI.GetPacketDetail(no)) as PacketDetail;
      setPacketDetail(detail);
    } catch (err: any) {
      pushToast('error', String(err));
    }
  };

  const openInstallModal = (pkgId?: string) => {
    setInstallInitPkgId(pkgId);
    setInstallProgress(null);
    setInstallOpen(true);
  };

  const handleStartOfflineInstall = async (pkgId: string) => {
    setInstalling(true);
    setInstallProgress(null);
    try {
      const updatedEnv = (await AppAPI.AutoInstallTcpdump(pkgId)) as ServerEnvInfo;
      setEnv(updatedEnv);
      pushToast('success', `tcpdump 离线安装成功 (${updatedEnv.tcpdumpPath})`);
    } catch (err: any) {
      pushToast('error', String(err));
    } finally {
      setInstalling(false);
    }
  };

  const handleImportPackage = async (data: {
    srcPath: string;
    name: string;
    version: string;
    arch: string;
    format: string;
    osTypes: string[];
    desc: string;
  }) => {
    try {
      await AppAPI.ImportOfflinePackage(
        data.srcPath,
        data.name,
        data.version,
        data.arch,
        data.format,
        data.osTypes,
        data.desc
      );
      const list = await AppAPI.ListOfflinePackages();
      setPackages((list || []) as OfflinePackage[]);
      pushToast('success', `已导入离线包：${data.name}`);
    } catch (err: any) {
      pushToast('error', String(err));
    }
  };

  const handleDeletePackage = async (pkgId: string) => {
    try {
      await AppAPI.DeleteOfflinePackage(pkgId);
      const list = await AppAPI.ListOfflinePackages();
      setPackages((list || []) as OfflinePackage[]);
      pushToast('info', '已删除自定义离线包');
    } catch (err: any) {
      pushToast('error', String(err));
    }
  };

  const handlePickKeyFile = async () => {
    return (await AppAPI.SelectFileForDialog('选择 SSH 私钥文件', '私钥文件 (*.pem;*.key;id_*)', '*.pem;*.key;*')) || '';
  };

  const handlePickPackageFile = async () => {
    return (await AppAPI.SelectFileForDialog('选择 tcpdump 离线安装包', '离线安装包 (*.rpm;*.deb;*.tar.gz;*.tgz;*)', '*.rpm;*.deb;*.tar.gz;*.tgz;*')) || '';
  };

  const handleClearLogs = async () => {
    await AppAPI.ClearLogs();
    setLogs([]);
  };

  return (
    <div className="app-shell">
      {/* Left Navigation Sidebar */}
      <aside className="sidebar">
        <div>
          <div className="brand-header">
            <div className="brand-icon">
              <Activity size={17} strokeWidth={2.2} />
            </div>
            <div>
              <div className="brand-title">NetProbe</div>
              <div className="brand-sub">SSH 远程抓包分析工具</div>
            </div>
          </div>

          <nav className="nav-list">
            <button
              className={`nav-item ${activeTab === 'capture' ? 'active' : ''}`}
              onClick={() => setActiveTab('capture')}
            >
              <Activity size={16} />
              <span>实时抓包</span>
              {stats.totalPackets > 0 && <span className="nav-badge">{stats.totalPackets}</span>}
            </button>

            <button
              className={`nav-item ${activeTab === 'servers' ? 'active' : ''}`}
              onClick={() => setActiveTab('servers')}
            >
              <Server size={16} />
              <span>服务器管理</span>
              <span className="nav-badge">{profiles.length}</span>
            </button>

            <button
              className={`nav-item ${activeTab === 'packages' ? 'active' : ''}`}
              onClick={() => setActiveTab('packages')}
            >
              <Package size={16} />
              <span>离线安装库</span>
              <span className="nav-badge">{packages.length}</span>
            </button>

            <button
              className={`nav-item ${activeTab === 'logs' ? 'active' : ''}`}
              onClick={() => setActiveTab('logs')}
            >
              <ScrollText size={16} />
              <span>操作日志</span>
              {logs.length > 0 && <span className="nav-badge">{logs.length}</span>}
            </button>
          </nav>
        </div>

        {/* Bottom Connection Card */}
        <div className="conn-card">
          <div className="conn-card-header">
            <span
              className={`status-dot ${
                stats.running ? 'capturing' : env.connected ? 'online' : ''
              }`}
            />
            <span className="conn-host" title={env.connected ? `${env.username}@${env.host}` : '未连接'}>
              {env.connected ? env.profileName || env.host : '未连接服务器'}
            </span>
          </div>

          {env.connected ? (
            <>
              <div className="conn-meta">
                <div>{env.osName}</div>
                <div style={{ display: 'flex', gap: 5, marginTop: 4, flexWrap: 'wrap' }}>
                  <span className="tag tag-blue">{env.arch}</span>
                  {env.hasTcpdump ? (
                    <span className="tag tag-green">tcpdump 就绪</span>
                  ) : (
                    <span className="tag tag-amber">缺 tcpdump</span>
                  )}
                </div>
              </div>
              <div className="conn-actions">
                {!env.hasTcpdump && (
                  <button
                    className="btn btn-primary btn-sm"
                    style={{ flex: 1 }}
                    onClick={() => openInstallModal()}
                  >
                    <Download size={12} />
                    离线安装
                  </button>
                )}
                <button
                  className="btn btn-secondary btn-sm"
                  style={{ flex: env.hasTcpdump ? 1 : undefined }}
                  onClick={handleDisconnect}
                  title="断开连接"
                >
                  <Unplug size={12} />
                  {env.hasTcpdump ? '断开连接' : ''}
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="conn-meta">连接 Linux 服务器后即可自动识别架构并抓包</div>
              <button
                className="btn btn-primary btn-sm btn-block"
                onClick={() => setActiveTab('servers')}
              >
                选择服务器连接
              </button>
            </>
          )}
        </div>
      </aside>

      {/* Main Content Workspace */}
      <main className="main-content">
        {activeTab === 'capture' && (
          <CaptureWorkspace
            env={env}
            packets={packets}
            stats={stats}
            selectedNo={selectedNo}
            packetDetail={packetDetail}
            onStartCapture={handleStartCapture}
            onStopCapture={handleStopCapture}
            onClearPackets={handleClearPackets}
            onExportPcap={handleExportPcap}
            onSelectPacket={handleSelectPacket}
            onOpenInstallModal={() => openInstallModal()}
            onGoToServers={() => setActiveTab('servers')}
            onRefreshEnv={handleRefreshEnv}
          />
        )}

        {activeTab === 'servers' && (
          <ServerManager
            profiles={profiles}
            env={env}
            connectingId={connectingId}
            onSaveProfile={handleSaveProfile}
            onDeleteProfile={handleDeleteProfile}
            onConnect={handleConnect}
            onDisconnect={handleDisconnect}
            onPickKeyFile={handlePickKeyFile}
          />
        )}

        {activeTab === 'packages' && (
          <OfflineRepo
            packages={packages}
            env={env}
            onDeployPackage={(pkgId) => openInstallModal(pkgId)}
            onImportPackage={handleImportPackage}
            onDeletePackage={handleDeletePackage}
            onPickPackageFile={handlePickPackageFile}
          />
        )}

        {activeTab === 'logs' && <ActivityLogs logs={logs} onClearLogs={handleClearLogs} />}
      </main>

      {/* Offline Auto-Install Modal */}
      <InstallModal
        open={installOpen}
        env={env}
        packages={packages}
        initialPackageId={installInitPkgId}
        progress={installProgress}
        installing={installing}
        onClose={() => setInstallOpen(false)}
        onStartInstall={handleStartOfflineInstall}
      />

      {/* Toast Notifications */}
      <div className="toast-container">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.type}`}>
            {t.type === 'success' && <CheckCircle2 size={15} color="#16A34A" />}
            {t.type === 'error' && <XCircle size={15} color="#DC2626" />}
            {t.type === 'info' && <Info size={15} color="#1677FF" />}
            <span>{t.text}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default App;
