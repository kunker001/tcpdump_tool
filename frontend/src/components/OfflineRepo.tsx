import React, { useState } from 'react';
import {
  CheckCircle2,
  Cpu,
  Download,
  FolderOpen,
  Package,
  Plus,
  ShieldCheck,
  Trash2,
  X,
} from 'lucide-react';
import { OfflinePackage, ServerEnvInfo } from '../types';

interface OfflineRepoProps {
  packages: OfflinePackage[];
  env: ServerEnvInfo;
  onDeployPackage: (pkgId: string) => void;
  onImportPackage: (data: {
    srcPath: string;
    name: string;
    version: string;
    arch: string;
    format: string;
    osTypes: string[];
    desc: string;
  }) => Promise<void>;
  onDeletePackage: (pkgId: string) => Promise<void>;
  onPickPackageFile: () => Promise<string>;
}

export const OfflineRepo: React.FC<OfflineRepoProps> = ({
  packages,
  env,
  onDeployPackage,
  onImportPackage,
  onDeletePackage,
  onPickPackageFile,
}) => {
  const [importOpen, setImportOpen] = useState(false);
  const [srcPath, setSrcPath] = useState('');
  const [name, setName] = useState('');
  const [version, setVersion] = useState('4.99.4');
  const [arch, setArch] = useState('x86_64');
  const [format, setFormat] = useState('static-bin');
  const [osTypesStr, setOsTypesStr] = useState('linux-generic');
  const [desc, setDesc] = useState('');
  const [importing, setImporting] = useState(false);

  const handlePickFile = async () => {
    const fp = await onPickPackageFile();
    if (fp) {
      setSrcPath(fp);
      const base = fp.split(/[\\/]/).pop() || '';
      if (!name) setName(base);
      const lower = base.toLowerCase();
      if (lower.endsWith('.rpm')) setFormat('rpm');
      else if (lower.endsWith('.deb')) setFormat('deb');
      else if (lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) setFormat('tar.gz');
      else setFormat('static-bin');
    }
  };

  const handleImportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!srcPath.trim()) return;
    setImporting(true);
    try {
      const osTypes = osTypesStr
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      await onImportPackage({
        srcPath: srcPath.trim(),
        name: name.trim(),
        version: version.trim(),
        arch,
        format,
        osTypes: osTypes.length > 0 ? osTypes : ['linux-generic'],
        desc: desc.trim(),
      });
      setImportOpen(false);
      setSrcPath('');
      setName('');
      setDesc('');
    } finally {
      setImporting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: '100%', minHeight: 0 }}>
      {/* Info Banner */}
      <div className="banner banner-info">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <ShieldCheck size={16} color="#1677FF" style={{ flexShrink: 0 }} />
          <div>
            <strong>内置多架构静态离线安装包</strong>
            <span style={{ marginLeft: 8, color: '#1E3A8A' }}>
              已内置 x86_64、ARM64 (aarch64)、ARMv7 (armhf)、x86 (i386) 四个静态编译版 tcpdump，无需目标服务器联网或依赖 glibc/libpcap；也支持导入自定义 RPM/DEB/Tar 包。
            </span>
          </div>
        </div>
      </div>

      {/* Package Repository Table Panel */}
      <div className="panel" style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div className="panel-header">
          <div className="panel-title">
            <Package size={15} color="#1677FF" />
            离线安装包仓库
            <span className="tag">{packages.length} 个可用包</span>
          </div>
          <button className="btn btn-primary" onClick={() => setImportOpen(true)}>
            <Plus size={14} />
            导入自定义离线包
          </button>
        </div>

        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 250 }}>安装包名称</th>
                <th style={{ width: 95 }}>架构</th>
                <th style={{ width: 95 }}>格式</th>
                <th style={{ width: 90 }}>大小</th>
                <th style={{ width: 110 }}>来源</th>
                <th>适用系统说明</th>
                <th style={{ width: 160 }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {packages.map((pkg) => {
                const isMatched = env.connected && env.matchedPackageId === pkg.id;
                return (
                  <tr key={pkg.id} className={isMatched ? 'selected' : ''}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ fontWeight: 500 }} title={pkg.name}>
                          {pkg.name}
                        </span>
                        {isMatched && (
                          <span className="tag tag-blue" title="与当前已连接服务器的架构和系统匹配">
                            <CheckCircle2 size={11} />
                            推荐匹配
                          </span>
                        )}
                      </div>
                    </td>
                    <td>
                      <span className="tag tag-blue">
                        <Cpu size={11} />
                        {pkg.arch}
                      </span>
                    </td>
                    <td className="mono">{pkg.format}</td>
                    <td className="mono">{(pkg.size / 1024 / 1024).toFixed(2)} MB</td>
                    <td>
                      {pkg.builtin ? (
                        <span className="tag tag-green">软件内置</span>
                      ) : (
                        <span className="tag">用户导入</span>
                      )}
                    </td>
                    <td title={pkg.description} style={{ color: '#64748B' }}>
                      {pkg.description || pkg.osTypes.join(', ')}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button
                          className={`btn btn-sm ${isMatched ? 'btn-primary' : 'btn-secondary'}`}
                          disabled={!env.connected}
                          title={env.connected ? '离线部署到当前连接的服务器' : '请先连接 SSH 服务器'}
                          onClick={() => onDeployPackage(pkg.id)}
                        >
                          <Download size={12} />
                          部署安装
                        </button>
                        {!pkg.builtin && (
                          <button
                            className="btn btn-ghost btn-sm"
                            title="删除自定义离线包"
                            onClick={() => onDeletePackage(pkg.id)}
                          >
                            <Trash2 size={13} color="#94A3B8" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Import Custom Offline Package Modal */}
      {importOpen && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <div className="modal-title">导入自定义 tcpdump 离线安装包</div>
              <button className="btn btn-ghost btn-sm" onClick={() => setImportOpen(false)}>
                <X size={15} />
              </button>
            </div>
            <form onSubmit={handleImportSubmit}>
              <div className="modal-body">
                <div className="form-grid">
                  <div className="form-field full">
                    <label className="form-label">选择本地安装包文件 *</label>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <input
                        className="input input-mono"
                        style={{ flex: 1 }}
                        required
                        placeholder="支持静态二进制文件、.rpm、.deb、.tar.gz"
                        value={srcPath}
                        onChange={(e) => setSrcPath(e.target.value)}
                      />
                      <button type="button" className="btn btn-secondary" onClick={handlePickFile}>
                        <FolderOpen size={14} />
                        选择文件
                      </button>
                    </div>
                  </div>
                  <div className="form-field">
                    <label className="form-label">显示名称</label>
                    <input
                      className="input"
                      placeholder="例如：CentOS 7 tcpdump RPM"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                    />
                  </div>
                  <div className="form-field">
                    <label className="form-label">版本号</label>
                    <input
                      className="input input-mono"
                      value={version}
                      onChange={(e) => setVersion(e.target.value)}
                    />
                  </div>
                  <div className="form-field">
                    <label className="form-label">目标 CPU 架构</label>
                    <select className="select" value={arch} onChange={(e) => setArch(e.target.value)}>
                      <option value="x86_64">x86_64 (amd64)</option>
                      <option value="aarch64">aarch64 (arm64)</option>
                      <option value="armhf">armhf (armv7l)</option>
                      <option value="x86">x86 (i386/i686)</option>
                      <option value="mips64">mips64</option>
                      <option value="loongarch64">loongarch64</option>
                    </select>
                  </div>
                  <div className="form-field">
                    <label className="form-label">安装包格式</label>
                    <select className="select" value={format} onChange={(e) => setFormat(e.target.value)}>
                      <option value="static-bin">静态可执行文件 (static-bin)</option>
                      <option value="rpm">RPM 安装包 (.rpm)</option>
                      <option value="deb">DEB 安装包 (.deb)</option>
                      <option value="tar.gz">压缩归档 (.tar.gz)</option>
                    </select>
                  </div>
                  <div className="form-field full">
                    <label className="form-label">适用系统 ID（逗号分隔，用于自动匹配）</label>
                    <input
                      className="input input-mono"
                      placeholder="例如：centos, rhel, kylin 或 linux-generic"
                      value={osTypesStr}
                      onChange={(e) => setOsTypesStr(e.target.value)}
                    />
                  </div>
                  <div className="form-field full">
                    <label className="form-label">说明描述</label>
                    <input
                      className="input"
                      placeholder="可选说明"
                      value={desc}
                      onChange={(e) => setDesc(e.target.value)}
                    />
                  </div>
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setImportOpen(false)}>
                  取消
                </button>
                <button type="submit" className="btn btn-primary" disabled={importing || !srcPath}>
                  {importing ? '导入中...' : '确认导入'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
