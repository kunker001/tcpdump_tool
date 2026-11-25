import React, { useEffect, useState } from 'react';
import { Check, Cpu, Download, HardDrive, Loader2, X } from 'lucide-react';
import { InstallProgress, OfflinePackage, ServerEnvInfo } from '../types';

interface InstallModalProps {
  open: boolean;
  env: ServerEnvInfo;
  packages: OfflinePackage[];
  initialPackageId?: string;
  progress: InstallProgress | null;
  installing: boolean;
  onClose: () => void;
  onStartInstall: (packageId: string) => void;
}

const STEP_LABELS = ['检测环境', '匹配离线包', '上传安装包', '安装与赋权', '验证可用'];

export const InstallModal: React.FC<InstallModalProps> = ({
  open,
  env,
  packages,
  initialPackageId,
  progress,
  installing,
  onClose,
  onStartInstall,
}) => {
  const [selectedPkgId, setSelectedPkgId] = useState<string>('');

  useEffect(() => {
    if (open) {
      setSelectedPkgId(initialPackageId || env.matchedPackageId || (packages[0]?.id ?? ''));
    }
  }, [open, initialPackageId, env.matchedPackageId, packages]);

  if (!open) return null;

  const selectedPkg = packages.find((p) => p.id === selectedPkgId);
  const currentStep = progress?.step ?? 0;
  const isDone = progress?.status === 'done';
  const isErr = progress?.status === 'error';

  return (
    <div className="modal-backdrop">
      <div className="modal-card" style={{ width: 600 }}>
        <div className="modal-header">
          <div className="modal-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Download size={16} color="#1677FF" />
            自动离线安装 tcpdump
          </div>
          <button
            className="btn btn-ghost btn-sm"
            onClick={onClose}
            disabled={installing}
            title="关闭"
          >
            <X size={15} />
          </button>
        </div>

        <div className="modal-body">
          {/* Target server info summary */}
          <div
            style={{
              background: '#F7F9FC',
              border: '1px solid #E2E8F0',
              borderRadius: 5,
              padding: '10px 12px',
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: '6px 14px',
              fontSize: 12.5,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <HardDrive size={14} color="#64748B" />
              <span style={{ color: '#64748B' }}>目标主机：</span>
              <span className="mono" style={{ fontWeight: 600 }}>
                {env.host}
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Cpu size={14} color="#64748B" />
              <span style={{ color: '#64748B' }}>系统架构：</span>
              <span className="tag tag-blue">{env.arch || 'unknown'}</span>
            </div>
            <div style={{ gridColumn: '1 / -1', color: '#334155' }}>
              <span style={{ color: '#64748B' }}>操作系统：</span>
              {env.osName} {env.kernel ? `(Kernel ${env.kernel})` : ''}
            </div>
          </div>

          {/* Package selector */}
          <div className="form-field">
            <label className="form-label">选择要部署的离线安装包（已根据目标架构自动匹配）</label>
            <select
              className="select"
              value={selectedPkgId}
              disabled={installing}
              onChange={(e) => setSelectedPkgId(e.target.value)}
            >
              {packages.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.id === env.matchedPackageId ? '[推荐匹配] ' : ''}
                  {p.name} — {p.arch} / {p.format} ({(p.size / 1024 / 1024).toFixed(2)} MB)
                </option>
              ))}
            </select>
            {selectedPkg && (
              <div style={{ fontSize: 12, color: '#64748B', marginTop: 2 }}>
                {selectedPkg.description || `格式: ${selectedPkg.format} | SHA256: ${selectedPkg.sha256}`}
              </div>
            )}
          </div>

          {/* 5-step progress stepper */}
          <div style={{ marginTop: 4 }}>
            <div className="stepper">
              {STEP_LABELS.map((label, idx) => {
                const stepNum = idx + 1;
                let cls = 'step-item';
                if (isErr && stepNum === currentStep) {
                  cls += ' error';
                } else if (isDone || stepNum < currentStep) {
                  cls += ' done';
                } else if (stepNum === currentStep && installing) {
                  cls += ' active';
                }
                return (
                  <div key={label} className={cls}>
                    <div className="step-node">
                      {isDone || stepNum < currentStep ? <Check size={13} /> : stepNum}
                    </div>
                    <div className="step-label">{label}</div>
                  </div>
                );
              })}
            </div>

            {progress && (
              <div style={{ marginTop: 12 }}>
                <div className="progress-bar-track">
                  <div
                    className="progress-bar-fill"
                    style={{
                      width: `${progress.percent}%`,
                      background: isErr ? '#DC2626' : '#1677FF',
                    }}
                  />
                </div>
                <div
                  style={{
                    marginTop: 8,
                    padding: '8px 10px',
                    borderRadius: 4,
                    background: isErr ? '#FEF2F2' : isDone ? '#F0FDF4' : '#F7F9FC',
                    border: `1px solid ${isErr ? '#FECACA' : isDone ? '#BBF7D0' : '#E2E8F0'}`,
                    color: isErr ? '#B91C1C' : isDone ? '#15803D' : '#334155',
                    fontSize: 12,
                  }}
                >
                  <div style={{ fontWeight: 600, marginBottom: 2 }}>
                    {progress.title} ({progress.percent}%)
                  </div>
                  <div style={{ wordBreak: 'break-all' }}>{progress.detail}</div>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose} disabled={installing}>
            {isDone ? '完成' : '取消'}
          </button>
          {!isDone && (
            <button
              className="btn btn-primary"
              disabled={installing || !selectedPkgId}
              onClick={() => onStartInstall(selectedPkgId)}
            >
              {installing ? (
                <>
                  <Loader2 size={14} className="spin" />
                  正在离线部署...
                </>
              ) : (
                <>
                  <Download size={14} />
                  开始自动离线安装
                </>
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
