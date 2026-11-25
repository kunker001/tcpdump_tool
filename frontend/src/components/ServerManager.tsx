import React, { useState } from 'react';
import {
  Edit2,
  FolderOpen,
  Loader2,
  Plug,
  Plus,
  Server,
  Trash2,
  Unplug,
  X,
} from 'lucide-react';
import { ServerEnvInfo, ServerProfile } from '../types';
import { EmptyState } from './EmptyState';

interface ServerManagerProps {
  profiles: ServerProfile[];
  env: ServerEnvInfo;
  connectingId: string | null;
  onSaveProfile: (p: ServerProfile) => Promise<void>;
  onDeleteProfile: (id: string) => Promise<void>;
  onConnect: (p: ServerProfile) => Promise<void>;
  onDisconnect: () => void;
  onPickKeyFile: () => Promise<string>;
}

const EMPTY_PROFILE: ServerProfile = {
  id: '',
  name: '',
  host: '',
  port: 22,
  username: 'root',
  authType: 'password',
  password: '',
  privateKeyPath: '',
  passphrase: '',
  useSudo: false,
  sudoPassword: '',
  note: '',
  lastConnectedAt: '',
};

export const ServerManager: React.FC<ServerManagerProps> = ({
  profiles,
  env,
  connectingId,
  onSaveProfile,
  onDeleteProfile,
  onConnect,
  onDisconnect,
  onPickKeyFile,
}) => {
  const [modalOpen, setModalOpen] = useState(false);
  const [form, setForm] = useState<ServerProfile>(EMPTY_PROFILE);
  const [saving, setSaving] = useState(false);

  const openCreate = () => {
    setForm({ ...EMPTY_PROFILE });
    setModalOpen(true);
  };

  const openEdit = (p: ServerProfile) => {
    setForm({ ...p });
    setModalOpen(true);
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.host.trim()) return;
    setSaving(true);
    try {
      await onSaveProfile({
        ...form,
        name: form.name.trim() || form.host.trim(),
        host: form.host.trim(),
        port: Number(form.port) || 22,
        username: form.username.trim() || 'root',
      });
      setModalOpen(false);
    } finally {
      setSaving(false);
    }
  };

  const handlePickKey = async () => {
    const path = await onPickKeyFile();
    if (path) {
      setForm((prev) => ({ ...prev, privateKeyPath: path }));
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, height: '100%', minHeight: 0 }}>
      {/* Current Connected Server Summary Card */}
      {env.connected && (
        <div className="panel" style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: 6,
                background: '#EBF5FF',
                border: '1px solid #BFDBFE',
                color: '#1677FF',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Server size={18} />
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: 13.5, display: 'flex', alignItems: 'center', gap: 8 }}>
                <span>{env.profileName || env.host}</span>
                <span className="tag tag-green">已连接</span>
                <span className="tag tag-blue">{env.arch}</span>
                {env.hasTcpdump ? (
                  <span className="tag tag-green">tcpdump 就绪</span>
                ) : (
                  <span className="tag tag-amber">未安装 tcpdump</span>
                )}
              </div>
              <div style={{ fontSize: 12, color: '#64748B', marginTop: 2 }}>
                {env.username}@{env.host}:{env.port} · {env.osName} · Kernel {env.kernel || '-'}
              </div>
            </div>
          </div>

          <button className="btn btn-secondary" onClick={onDisconnect}>
            <Unplug size={14} />
            断开连接
          </button>
        </div>
      )}

      {/* Server Profiles List Panel */}
      <div className="panel" style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div className="panel-header">
          <div className="panel-title">
            <Server size={15} color="#1677FF" />
            SSH 服务器列表
            <span className="tag">{profiles.length}</span>
          </div>
          <button className="btn btn-primary" onClick={openCreate}>
            <Plus size={14} />
            新建服务器
          </button>
        </div>

        {profiles.length === 0 ? (
          <EmptyState
            variant="servers"
            title="暂无保存的 SSH 服务器"
            description="点击右上角「新建服务器」配置主机地址与认证方式，支持密码与私钥认证。"
            action={
              <button className="btn btn-primary" onClick={openCreate}>
                <Plus size={14} />
                添加第一台服务器
              </button>
            }
          />
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 170 }}>名称</th>
                  <th style={{ width: 180 }}>主机地址</th>
                  <th style={{ width: 110 }}>用户名</th>
                  <th style={{ width: 90 }}>认证方式</th>
                  <th>备注</th>
                  <th style={{ width: 150 }}>最近连接</th>
                  <th style={{ width: 180 }}>操作</th>
                </tr>
              </thead>
              <tbody>
                {profiles.map((p) => {
                  const isCurrent = env.connected && env.profileId === p.id;
                  const isConnecting = connectingId === p.id;
                  return (
                    <tr key={p.id} className={isCurrent ? 'selected' : ''}>
                      <td style={{ fontWeight: 500 }}>{p.name}</td>
                      <td className="mono">
                        {p.host}:{p.port}
                      </td>
                      <td className="mono">{p.username}</td>
                      <td>
                        <span className="tag">{p.authType === 'key' ? '私钥' : '密码'}</span>
                      </td>
                      <td style={{ color: '#64748B' }}>{p.note || '-'}</td>
                      <td className="mono" style={{ color: '#64748B', fontSize: 11.5 }}>
                        {p.lastConnectedAt || '-'}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6 }}>
                          {isCurrent ? (
                            <button className="btn btn-secondary btn-sm" onClick={onDisconnect}>
                              断开
                            </button>
                          ) : (
                            <button
                              className="btn btn-primary btn-sm"
                              disabled={connectingId !== null}
                              onClick={() => onConnect(p)}
                            >
                              {isConnecting ? (
                                <Loader2 size={12} className="spin" />
                              ) : (
                                <Plug size={12} />
                              )}
                              {isConnecting ? '连接中' : '连接'}
                            </button>
                          )}
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => openEdit(p)}
                            title="编辑"
                          >
                            <Edit2 size={12} />
                          </button>
                          <button
                            className="btn btn-ghost btn-sm"
                            onClick={() => onDeleteProfile(p.id)}
                            title="删除"
                          >
                            <Trash2 size={13} color="#94A3B8" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add / Edit Server Modal */}
      {modalOpen && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <div className="modal-title">{form.id ? '编辑服务器配置' : '新建 SSH 服务器'}</div>
              <button className="btn btn-ghost btn-sm" onClick={() => setModalOpen(false)}>
                <X size={15} />
              </button>
            </div>
            <form onSubmit={handleSave}>
              <div className="modal-body">
                <div className="form-grid">
                  <div className="form-field full">
                    <label className="form-label">显示名称</label>
                    <input
                      className="input"
                      placeholder="例如：生产网关服务器-01"
                      value={form.name}
                      onChange={(e) => setForm({ ...form, name: e.target.value })}
                    />
                  </div>
                  <div className="form-field">
                    <label className="form-label">主机 IP / 域名 *</label>
                    <input
                      className="input input-mono"
                      required
                      placeholder="192.168.1.100"
                      value={form.host}
                      onChange={(e) => setForm({ ...form, host: e.target.value })}
                    />
                  </div>
                  <div className="form-field">
                    <label className="form-label">SSH 端口</label>
                    <input
                      type="number"
                      className="input input-mono"
                      value={form.port}
                      onChange={(e) => setForm({ ...form, port: parseInt(e.target.value, 10) || 22 })}
                    />
                  </div>
                  <div className="form-field">
                    <label className="form-label">用户名</label>
                    <input
                      className="input input-mono"
                      value={form.username}
                      onChange={(e) => setForm({ ...form, username: e.target.value })}
                    />
                  </div>
                  <div className="form-field">
                    <label className="form-label">认证方式</label>
                    <select
                      className="select"
                      value={form.authType}
                      onChange={(e) =>
                        setForm({ ...form, authType: e.target.value as 'password' | 'key' })
                      }
                    >
                      <option value="password">密码认证</option>
                      <option value="key">SSH 私钥认证</option>
                    </select>
                  </div>

                  {form.authType === 'password' ? (
                    <div className="form-field full">
                      <label className="form-label">登录密码</label>
                      <input
                        type="password"
                        className="input"
                        placeholder="请输入 SSH 登录密码"
                        value={form.password}
                        onChange={(e) => setForm({ ...form, password: e.target.value })}
                      />
                    </div>
                  ) : (
                    <>
                      <div className="form-field full">
                        <label className="form-label">私钥文件路径</label>
                        <div style={{ display: 'flex', gap: 6 }}>
                          <input
                            className="input input-mono"
                            style={{ flex: 1 }}
                            placeholder="例如：C:\Users\...\id_rsa"
                            value={form.privateKeyPath}
                            onChange={(e) => setForm({ ...form, privateKeyPath: e.target.value })}
                          />
                          <button type="button" className="btn btn-secondary" onClick={handlePickKey}>
                            <FolderOpen size={14} />
                            浏览
                          </button>
                        </div>
                      </div>
                      <div className="form-field full">
                        <label className="form-label">私钥口令（如无请留空）</label>
                        <input
                          type="password"
                          className="input"
                          value={form.passphrase}
                          onChange={(e) => setForm({ ...form, passphrase: e.target.value })}
                        />
                      </div>
                    </>
                  )}

                  <div className="form-field full">
                    <label className="checkbox-label">
                      <input
                        type="checkbox"
                        checked={form.useSudo}
                        onChange={(e) => setForm({ ...form, useSudo: e.target.checked })}
                      />
                      非 root 账号时使用 sudo 提权运行 tcpdump 与离线安装
                    </label>
                  </div>

                  {form.useSudo && (
                    <div className="form-field full">
                      <label className="form-label">sudo 密码（留空则复用 SSH 密码）</label>
                      <input
                        type="password"
                        className="input"
                        value={form.sudoPassword}
                        onChange={(e) => setForm({ ...form, sudoPassword: e.target.value })}
                      />
                    </div>
                  )}

                  <div className="form-field full">
                    <label className="form-label">备注</label>
                    <input
                      className="input"
                      placeholder="可选说明信息"
                      value={form.note}
                      onChange={(e) => setForm({ ...form, note: e.target.value })}
                    />
                  </div>
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setModalOpen(false)}>
                  取消
                </button>
                <button type="submit" className="btn btn-primary" disabled={saving}>
                  {saving ? '保存中...' : '保存配置'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
