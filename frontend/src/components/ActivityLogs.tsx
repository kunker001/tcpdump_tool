import React, { useState } from 'react';
import { ScrollText, Trash2 } from 'lucide-react';
import { LogEntry } from '../types';
import { EmptyState } from './EmptyState';

interface ActivityLogsProps {
  logs: LogEntry[];
  onClearLogs: () => void;
}

export const ActivityLogs: React.FC<ActivityLogsProps> = ({ logs, onClearLogs }) => {
  const [levelFilter, setLevelFilter] = useState<string>('all');

  const filtered = levelFilter === 'all' ? logs : logs.filter((l) => l.level === levelFilter);

  const levelBadge = (level: LogEntry['level']) => {
    switch (level) {
      case 'success':
        return <span className="tag tag-green">成功</span>;
      case 'warn':
        return <span className="tag tag-amber">警告</span>;
      case 'error':
        return <span className="tag tag-red">错误</span>;
      default:
        return <span className="tag tag-blue">信息</span>;
    }
  };

  return (
    <div className="panel" style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div className="panel-header">
        <div className="panel-title">
          <ScrollText size={15} color="#1677FF" />
          运行与操作日志
          <span className="tag">{filtered.length}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <select
            className="select"
            style={{ height: 28, fontSize: 12 }}
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
          >
            <option value="all">全部级别</option>
            <option value="info">信息</option>
            <option value="success">成功</option>
            <option value="warn">警告</option>
            <option value="error">错误</option>
          </select>
          <button className="btn btn-secondary btn-sm" disabled={logs.length === 0} onClick={onClearLogs}>
            <Trash2 size={13} />
            清空日志
          </button>
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          variant="logs"
          title="暂无操作日志"
          description="SSH 连接、离线包安装、tcpdump 启动与导出等操作记录将实时汇聚于此。"
        />
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 96 }}>时间</th>
                <th style={{ width: 78 }}>级别</th>
                <th style={{ width: 92 }}>模块</th>
                <th>日志详情</th>
              </tr>
            </thead>
            <tbody>
              {[...filtered].reverse().map((l) => (
                <tr key={l.id}>
                  <td className="mono" style={{ color: '#64748B' }}>
                    {l.time}
                  </td>
                  <td>{levelBadge(l.level)}</td>
                  <td style={{ fontWeight: 500 }}>{l.source}</td>
                  <td title={l.message}>{l.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
