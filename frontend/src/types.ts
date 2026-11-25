export interface ServerProfile {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  authType: 'password' | 'key';
  password: string;
  privateKeyPath: string;
  passphrase: string;
  useSudo: boolean;
  sudoPassword: string;
  note: string;
  lastConnectedAt: string;
}

export interface NetInterface {
  name: string;
  ip: string;
  state: string;
  description: string;
}

export interface ServerEnvInfo {
  connected: boolean;
  profileId: string;
  profileName: string;
  host: string;
  port: number;
  username: string;
  osName: string;
  osId: string;
  osVersion: string;
  kernel: string;
  arch: string;
  normalizedArch: string;
  hasTcpdump: boolean;
  tcpdumpPath: string;
  tcpdumpVersion: string;
  isRoot: boolean;
  canSudo: boolean;
  interfaces: NetInterface[];
  matchedPackageId: string;
}

export interface OfflinePackage {
  id: string;
  name: string;
  version: string;
  arch: string;
  osTypes: string[];
  format: string;
  size: number;
  sha256: string;
  builtin: boolean;
  fileName: string;
  description: string;
}

export interface InstallProgress {
  step: number;
  totalSteps: number;
  title: string;
  detail: string;
  status: 'running' | 'done' | 'error';
  percent: number;
}

export interface CaptureConfig {
  interface: string;
  srcIp: string;
  dstIp: string;
  filter: string;
  maxPackets: number;
  snaplen: number;
  excludeSsh: boolean;
  promiscuous: boolean;
}

export interface PacketSummary {
  no: number;
  timestamp: string;
  srcAddr: string;
  dstAddr: string;
  protocol: string;
  length: number;
  info: string;
}

export interface LayerField {
  key: string;
  value: string;
}

export interface ProtocolLayer {
  name: string;
  summary: string;
  fields: LayerField[];
}

export interface HexLine {
  offset: string;
  hex: string;
  ascii: string;
}

export interface PacketDetail {
  summary: PacketSummary;
  layers: ProtocolLayer[];
  hexDump: HexLine[];
  rawLen: number;
}

export interface CaptureStats {
  running: boolean;
  totalPackets: number;
  totalBytes: number;
  elapsedSec: number;
  packetsPerSec: number;
  bytesPerSec: number;
  protocols: Record<string, number>;
  command: string;
}

export interface LogEntry {
  id: number;
  time: string;
  level: 'info' | 'success' | 'warn' | 'error';
  source: string;
  message: string;
}

export type NavTab = 'capture' | 'servers' | 'packages' | 'logs';
