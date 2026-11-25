export namespace models {
	
	export class CaptureConfig {
	    interface: string;
	    srcIp: string;
	    dstIp: string;
	    filter: string;
	    maxPackets: number;
	    snaplen: number;
	    excludeSsh: boolean;
	    promiscuous: boolean;
	
	    static createFrom(source: any = {}) {
	        return new CaptureConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.interface = source["interface"];
	        this.srcIp = source["srcIp"];
	        this.dstIp = source["dstIp"];
	        this.filter = source["filter"];
	        this.maxPackets = source["maxPackets"];
	        this.snaplen = source["snaplen"];
	        this.excludeSsh = source["excludeSsh"];
	        this.promiscuous = source["promiscuous"];
	    }
	}
	export class CaptureStats {
	    running: boolean;
	    totalPackets: number;
	    totalBytes: number;
	    elapsedSec: number;
	    packetsPerSec: number;
	    bytesPerSec: number;
	    protocols: Record<string, number>;
	    command: string;
	
	    static createFrom(source: any = {}) {
	        return new CaptureStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.totalPackets = source["totalPackets"];
	        this.totalBytes = source["totalBytes"];
	        this.elapsedSec = source["elapsedSec"];
	        this.packetsPerSec = source["packetsPerSec"];
	        this.bytesPerSec = source["bytesPerSec"];
	        this.protocols = source["protocols"];
	        this.command = source["command"];
	    }
	}
	export class HexLine {
	    offset: string;
	    hex: string;
	    ascii: string;
	
	    static createFrom(source: any = {}) {
	        return new HexLine(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.offset = source["offset"];
	        this.hex = source["hex"];
	        this.ascii = source["ascii"];
	    }
	}
	export class LayerField {
	    key: string;
	    value: string;
	
	    static createFrom(source: any = {}) {
	        return new LayerField(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.value = source["value"];
	    }
	}
	export class LogEntry {
	    id: number;
	    time: string;
	    level: string;
	    source: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new LogEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.time = source["time"];
	        this.level = source["level"];
	        this.source = source["source"];
	        this.message = source["message"];
	    }
	}
	export class NetInterface {
	    name: string;
	    ip: string;
	    state: string;
	    description: string;
	
	    static createFrom(source: any = {}) {
	        return new NetInterface(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.ip = source["ip"];
	        this.state = source["state"];
	        this.description = source["description"];
	    }
	}
	export class OfflinePackage {
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
	
	    static createFrom(source: any = {}) {
	        return new OfflinePackage(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.version = source["version"];
	        this.arch = source["arch"];
	        this.osTypes = source["osTypes"];
	        this.format = source["format"];
	        this.size = source["size"];
	        this.sha256 = source["sha256"];
	        this.builtin = source["builtin"];
	        this.fileName = source["fileName"];
	        this.description = source["description"];
	    }
	}
	export class ProtocolLayer {
	    name: string;
	    summary: string;
	    fields: LayerField[];
	
	    static createFrom(source: any = {}) {
	        return new ProtocolLayer(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.summary = source["summary"];
	        this.fields = this.convertValues(source["fields"], LayerField);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PacketSummary {
	    no: number;
	    timestamp: string;
	    srcAddr: string;
	    dstAddr: string;
	    protocol: string;
	    length: number;
	    info: string;
	
	    static createFrom(source: any = {}) {
	        return new PacketSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.no = source["no"];
	        this.timestamp = source["timestamp"];
	        this.srcAddr = source["srcAddr"];
	        this.dstAddr = source["dstAddr"];
	        this.protocol = source["protocol"];
	        this.length = source["length"];
	        this.info = source["info"];
	    }
	}
	export class PacketDetail {
	    summary: PacketSummary;
	    layers: ProtocolLayer[];
	    hexDump: HexLine[];
	    rawLen: number;
	
	    static createFrom(source: any = {}) {
	        return new PacketDetail(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.summary = this.convertValues(source["summary"], PacketSummary);
	        this.layers = this.convertValues(source["layers"], ProtocolLayer);
	        this.hexDump = this.convertValues(source["hexDump"], HexLine);
	        this.rawLen = source["rawLen"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	export class ServerEnvInfo {
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
	
	    static createFrom(source: any = {}) {
	        return new ServerEnvInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.connected = source["connected"];
	        this.profileId = source["profileId"];
	        this.profileName = source["profileName"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.username = source["username"];
	        this.osName = source["osName"];
	        this.osId = source["osId"];
	        this.osVersion = source["osVersion"];
	        this.kernel = source["kernel"];
	        this.arch = source["arch"];
	        this.normalizedArch = source["normalizedArch"];
	        this.hasTcpdump = source["hasTcpdump"];
	        this.tcpdumpPath = source["tcpdumpPath"];
	        this.tcpdumpVersion = source["tcpdumpVersion"];
	        this.isRoot = source["isRoot"];
	        this.canSudo = source["canSudo"];
	        this.interfaces = this.convertValues(source["interfaces"], NetInterface);
	        this.matchedPackageId = source["matchedPackageId"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ServerProfile {
	    id: string;
	    name: string;
	    host: string;
	    port: number;
	    username: string;
	    authType: string;
	    password: string;
	    privateKeyPath: string;
	    passphrase: string;
	    useSudo: boolean;
	    sudoPassword: string;
	    note: string;
	    lastConnectedAt: string;
	
	    static createFrom(source: any = {}) {
	        return new ServerProfile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.username = source["username"];
	        this.authType = source["authType"];
	        this.password = source["password"];
	        this.privateKeyPath = source["privateKeyPath"];
	        this.passphrase = source["passphrase"];
	        this.useSudo = source["useSudo"];
	        this.sudoPassword = source["sudoPassword"];
	        this.note = source["note"];
	        this.lastConnectedAt = source["lastConnectedAt"];
	    }
	}

}

