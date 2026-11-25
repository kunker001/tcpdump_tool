package pcap

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"ssh-packet-capture/internal/models"
)

const (
	magicLittleMicro = 0xa1b2c3d4
	magicBigMicro    = 0xd4c3b2a1
	magicLittleNano  = 0xa1b23c4d
	magicBigNano     = 0x4d3cb2a1
)

// GlobalHeader represents the 24-byte libpcap file header.
type GlobalHeader struct {
	Raw          [24]byte
	ByteOrder    binary.ByteOrder
	Nano         bool
	VersionMajor uint16
	VersionMinor uint16
	Snaplen      uint32
	LinkType     uint32
}

// RawPacket holds one captured packet record from the pcap stream.
type RawPacket struct {
	No        int
	Timestamp time.Time
	OrigLen   int
	InclLen   int
	LinkType  uint32
	HeaderRaw [16]byte
	Data      []byte
	Summary   models.PacketSummary
}

// StreamReader reads a standard libpcap stream from an io.Reader (e.g., tcpdump -w -).
type StreamReader struct {
	r      *bufio.Reader
	Header GlobalHeader
}

// NewStreamReader reads the 24-byte libpcap global header and returns a StreamReader.
func NewStreamReader(r io.Reader) (*StreamReader, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	var raw [24]byte
	if _, err := io.ReadFull(br, raw[:]); err != nil {
		return nil, fmt.Errorf("读取 PCAP 文件头失败: %w", err)
	}

	magic := binary.LittleEndian.Uint32(raw[0:4])
	var hdr GlobalHeader
	hdr.Raw = raw
	switch magic {
	case magicLittleMicro:
		hdr.ByteOrder = binary.LittleEndian
		hdr.Nano = false
	case magicBigMicro:
		hdr.ByteOrder = binary.BigEndian
		hdr.Nano = false
	case magicLittleNano:
		hdr.ByteOrder = binary.LittleEndian
		hdr.Nano = true
	case magicBigNano:
		hdr.ByteOrder = binary.BigEndian
		hdr.Nano = true
	default:
		return nil, fmt.Errorf("无效的 PCAP 魔数: 0x%08x (tcpdump 输出异常)", magic)
	}

	hdr.VersionMajor = hdr.ByteOrder.Uint16(raw[4:6])
	hdr.VersionMinor = hdr.ByteOrder.Uint16(raw[6:8])
	hdr.Snaplen = hdr.ByteOrder.Uint32(raw[16:20])
	hdr.LinkType = hdr.ByteOrder.Uint32(raw[20:24])

	return &StreamReader{
		r:      br,
		Header: hdr,
	}, nil
}

// ReadNext reads the next packet record from the pcap stream.
func (sr *StreamReader) ReadNext(no int) (*RawPacket, error) {
	var recHdr [16]byte
	if _, err := io.ReadFull(sr.r, recHdr[:]); err != nil {
		return nil, err
	}

	bo := sr.Header.ByteOrder
	tsSec := bo.Uint32(recHdr[0:4])
	tsSub := bo.Uint32(recHdr[4:8])
	inclLen := bo.Uint32(recHdr[8:12])
	origLen := bo.Uint32(recHdr[12:16])

	if inclLen > 262144 {
		return nil, fmt.Errorf("异常数据包长度: %d", inclLen)
	}

	data := make([]byte, inclLen)
	if _, err := io.ReadFull(sr.r, data); err != nil {
		return nil, err
	}

	var ts time.Time
	if sr.Header.Nano {
		ts = time.Unix(int64(tsSec), int64(tsSub))
	} else {
		ts = time.Unix(int64(tsSec), int64(tsSub)*1000)
	}

	pkt := &RawPacket{
		No:        no,
		Timestamp: ts,
		OrigLen:   int(origLen),
		InclLen:   int(inclLen),
		LinkType:  sr.Header.LinkType,
		HeaderRaw: recHdr,
		Data:      data,
	}
	pkt.Summary = SummarizePacket(pkt)
	return pkt, nil
}

// SummarizePacket extracts lightweight summary fields for table rendering.
func SummarizePacket(pkt *RawPacket) models.PacketSummary {
	detail := DissectPacket(pkt, false)
	return detail.Summary
}

// DissectPacket parses protocol layers and optionally builds a hex dump.
func DissectPacket(pkt *RawPacket, includeHex bool) models.PacketDetail {
	summary := models.PacketSummary{
		No:        pkt.No,
		Timestamp: pkt.Timestamp.Format("15:04:05.000000"),
		SrcAddr:   "-",
		DstAddr:   "-",
		Protocol:  "UNKNOWN",
		Length:    pkt.OrigLen,
		Info:      fmt.Sprintf("LinkType %d, %d bytes", pkt.LinkType, pkt.OrigLen),
	}

	layers := []models.ProtocolLayer{
		{
			Name:    "Frame (帧信息)",
			Summary: fmt.Sprintf("第 %d 帧，捕获 %d 字节 / 线路 %d 字节", pkt.No, pkt.InclLen, pkt.OrigLen),
			Fields: []models.LayerField{
				{Key: "序号", Value: fmt.Sprintf("%d", pkt.No)},
				{Key: "捕获时间", Value: pkt.Timestamp.Format("2006-01-02 15:04:05.000000")},
				{Key: "捕获长度", Value: fmt.Sprintf("%d bytes", pkt.InclLen)},
				{Key: "原始长度", Value: fmt.Sprintf("%d bytes", pkt.OrigLen)},
				{Key: "链路类型", Value: linkTypeName(pkt.LinkType)},
			},
		},
	}

	etherType, payload, linkLayer := parseLinkLayer(pkt.LinkType, pkt.Data)
	if linkLayer != nil {
		layers = append(layers, *linkLayer)
	}

	// Unwrap 802.1Q VLAN tag(s) if present
	for etherType == 0x8100 || etherType == 0x88a8 {
		if len(payload) < 4 {
			break
		}
		tci := binary.BigEndian.Uint16(payload[0:2])
		vlanID := tci & 0x0fff
		etherType = binary.BigEndian.Uint16(payload[2:4])
		layers = append(layers, models.ProtocolLayer{
			Name:    "802.1Q VLAN",
			Summary: fmt.Sprintf("VLAN ID: %d", vlanID),
			Fields: []models.LayerField{
				{Key: "VLAN ID", Value: fmt.Sprintf("%d", vlanID)},
				{Key: "封装类型", Value: fmt.Sprintf("0x%04x", etherType)},
			},
		})
		payload = payload[4:]
	}

	switch etherType {
	case 0x0806: // ARP
		parseARP(payload, &summary, &layers)
	case 0x0800: // IPv4
		parseIPv4(payload, &summary, &layers)
	case 0x86dd: // IPv6
		parseIPv6(payload, &summary, &layers)
	default:
		if linkLayer != nil && len(linkLayer.Fields) >= 2 {
			summary.SrcAddr = linkLayer.Fields[0].Value
			summary.DstAddr = linkLayer.Fields[1].Value
		}
		summary.Protocol = fmt.Sprintf("0x%04X", etherType)
		summary.Info = fmt.Sprintf("EtherType 0x%04x, payload %d bytes", etherType, len(payload))
	}

	detail := models.PacketDetail{
		Summary: summary,
		Layers:  layers,
		RawLen:  len(pkt.Data),
	}
	if includeHex {
		detail.HexDump = buildHexDump(pkt.Data)
	}
	return detail
}

func linkTypeName(lt uint32) string {
	switch lt {
	case 1:
		return "Ethernet (1)"
	case 12, 101:
		return "Raw IP (101)"
	case 113:
		return "Linux Cooked SLL (113)"
	case 276:
		return "Linux Cooked SLL2 (276)"
	default:
		return fmt.Sprintf("Unknown (%d)", lt)
	}
}

func parseLinkLayer(linkType uint32, data []byte) (uint16, []byte, *models.ProtocolLayer) {
	switch linkType {
	case 1: // Ethernet II
		if len(data) < 14 {
			return 0, nil, nil
		}
		dstMAC := net.HardwareAddr(data[0:6]).String()
		srcMAC := net.HardwareAddr(data[6:12]).String()
		etherType := binary.BigEndian.Uint16(data[12:14])
		layer := &models.ProtocolLayer{
			Name:    "Ethernet II (以太网帧)",
			Summary: fmt.Sprintf("%s → %s (0x%04x)", srcMAC, dstMAC, etherType),
			Fields: []models.LayerField{
				{Key: "源 MAC", Value: srcMAC},
				{Key: "目的 MAC", Value: dstMAC},
				{Key: "上层协议", Value: fmt.Sprintf("0x%04x", etherType)},
			},
		}
		return etherType, data[14:], layer

	case 113: // Linux SLL (tcpdump -i any)
		if len(data) < 16 {
			return 0, nil, nil
		}
		pktType := binary.BigEndian.Uint16(data[0:2])
		addrLen := binary.BigEndian.Uint16(data[4:6])
		if addrLen > 8 {
			addrLen = 8
		}
		srcAddr := net.HardwareAddr(data[6 : 6+addrLen]).String()
		proto := binary.BigEndian.Uint16(data[14:16])
		layer := &models.ProtocolLayer{
			Name:    "Linux Cooked Capture (SLL)",
			Summary: fmt.Sprintf("方向: %s, 协议: 0x%04x", sllPktType(pktType), proto),
			Fields: []models.LayerField{
				{Key: "包类型", Value: sllPktType(pktType)},
				{Key: "源链路地址", Value: srcAddr},
				{Key: "协议类型", Value: fmt.Sprintf("0x%04x", proto)},
			},
		}
		return proto, data[16:], layer

	case 276: // Linux SLL2 (newer tcpdump -i any)
		if len(data) < 20 {
			return 0, nil, nil
		}
		proto := binary.BigEndian.Uint16(data[0:2])
		ifIdx := binary.BigEndian.Uint32(data[4:8])
		pktType := uint16(data[10])
		addrLen := int(data[11])
		if addrLen > 8 {
			addrLen = 8
		}
		srcAddr := net.HardwareAddr(data[12 : 12+addrLen]).String()
		layer := &models.ProtocolLayer{
			Name:    "Linux Cooked Capture v2 (SLL2)",
			Summary: fmt.Sprintf("接口索引 #%d, 方向: %s, 协议: 0x%04x", ifIdx, sllPktType(pktType), proto),
			Fields: []models.LayerField{
				{Key: "接口索引", Value: fmt.Sprintf("%d", ifIdx)},
				{Key: "包类型", Value: sllPktType(pktType)},
				{Key: "源链路地址", Value: srcAddr},
				{Key: "协议类型", Value: fmt.Sprintf("0x%04x", proto)},
			},
		}
		return proto, data[20:], layer

	case 12, 101: // Raw IP
		if len(data) < 1 {
			return 0, nil, nil
		}
		ver := data[0] >> 4
		if ver == 4 {
			return 0x0800, data, nil
		}
		if ver == 6 {
			return 0x86dd, data, nil
		}
		return 0, data, nil
	}
	return 0, data, nil
}

func sllPktType(t uint16) string {
	switch t {
	case 0:
		return "发往本机 (Unicast)"
	case 1:
		return "广播 (Broadcast)"
	case 2:
		return "组播 (Multicast)"
	case 3:
		return "发往其他主机"
	case 4:
		return "本机发出 (Outgoing)"
	default:
		return fmt.Sprintf("类型 %d", t)
	}
}

func parseARP(data []byte, summary *models.PacketSummary, layers *[]models.ProtocolLayer) {
	summary.Protocol = "ARP"
	if len(data) < 28 {
		summary.Info = "Malformed ARP packet"
		return
	}
	op := binary.BigEndian.Uint16(data[6:8])
	senderMAC := net.HardwareAddr(data[8:14]).String()
	senderIP := net.IP(data[14:18]).String()
	targetMAC := net.HardwareAddr(data[18:24]).String()
	targetIP := net.IP(data[24:28]).String()

	summary.SrcAddr = senderIP
	summary.DstAddr = targetIP
	opStr := fmt.Sprintf("Opcode %d", op)
	switch op {
	case 1:
		opStr = "Request (1)"
		summary.Info = fmt.Sprintf("Who has %s? Tell %s", targetIP, senderIP)
	case 2:
		opStr = "Reply (2)"
		summary.Info = fmt.Sprintf("%s is at %s", senderIP, senderMAC)
	}

	*layers = append(*layers, models.ProtocolLayer{
		Name:    "Address Resolution Protocol (ARP)",
		Summary: summary.Info,
		Fields: []models.LayerField{
			{Key: "操作类型", Value: opStr},
			{Key: "发送方 MAC", Value: senderMAC},
			{Key: "发送方 IP", Value: senderIP},
			{Key: "目标 MAC", Value: targetMAC},
			{Key: "目标 IP", Value: targetIP},
		},
	})
}

func parseIPv4(data []byte, summary *models.PacketSummary, layers *[]models.ProtocolLayer) {
	if len(data) < 20 {
		summary.Protocol = "IPv4"
		summary.Info = "Truncated IPv4 packet"
		return
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || ihl > len(data) {
		ihl = 20
	}
	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	id := binary.BigEndian.Uint16(data[4:6])
	ttl := data[8]
	proto := data[9]
	srcIP := net.IP(data[12:16]).String()
	dstIP := net.IP(data[16:20]).String()

	summary.SrcAddr = srcIP
	summary.DstAddr = dstIP

	*layers = append(*layers, models.ProtocolLayer{
		Name:    "Internet Protocol Version 4 (IPv4)",
		Summary: fmt.Sprintf("%s → %s, TTL=%d, 长度=%d", srcIP, dstIP, ttl, totalLen),
		Fields: []models.LayerField{
			{Key: "源 IP", Value: srcIP},
			{Key: "目的 IP", Value: dstIP},
			{Key: "首部长度", Value: fmt.Sprintf("%d bytes", ihl)},
			{Key: "总长度", Value: fmt.Sprintf("%d bytes", totalLen)},
			{Key: "标识 (ID)", Value: fmt.Sprintf("0x%04x (%d)", id, id)},
			{Key: "生存时间 (TTL)", Value: fmt.Sprintf("%d", ttl)},
			{Key: "上层协议", Value: ipProtoName(proto)},
		},
	})

	end := len(data)
	if totalLen >= ihl && totalLen < end {
		end = totalLen
	}
	payload := data[ihl:end]
	parseTransport(proto, payload, srcIP, dstIP, summary, layers)
}

func parseIPv6(data []byte, summary *models.PacketSummary, layers *[]models.ProtocolLayer) {
	if len(data) < 40 {
		summary.Protocol = "IPv6"
		summary.Info = "Truncated IPv6 packet"
		return
	}
	payloadLen := int(binary.BigEndian.Uint16(data[4:6]))
	nextHdr := data[6]
	hopLimit := data[7]
	srcIP := net.IP(data[8:24]).String()
	dstIP := net.IP(data[24:40]).String()

	summary.SrcAddr = srcIP
	summary.DstAddr = dstIP

	*layers = append(*layers, models.ProtocolLayer{
		Name:    "Internet Protocol Version 6 (IPv6)",
		Summary: fmt.Sprintf("%s → %s, HopLimit=%d", srcIP, dstIP, hopLimit),
		Fields: []models.LayerField{
			{Key: "源 IP", Value: srcIP},
			{Key: "目的 IP", Value: dstIP},
			{Key: "载荷长度", Value: fmt.Sprintf("%d bytes", payloadLen)},
			{Key: "跳数限制", Value: fmt.Sprintf("%d", hopLimit)},
			{Key: "下一首部", Value: ipProtoName(nextHdr)},
		},
	})

	parseTransport(nextHdr, data[40:], srcIP, dstIP, summary, layers)
}

func ipProtoName(p byte) string {
	switch p {
	case 1:
		return "ICMP (1)"
	case 6:
		return "TCP (6)"
	case 17:
		return "UDP (17)"
	case 58:
		return "ICMPv6 (58)"
	default:
		return fmt.Sprintf("Protocol %d", p)
	}
}

func parseTransport(proto byte, data []byte, srcIP, dstIP string, summary *models.PacketSummary, layers *[]models.ProtocolLayer) {
	switch proto {
	case 6: // TCP
		parseTCP(data, srcIP, dstIP, summary, layers)
	case 17: // UDP
		parseUDP(data, srcIP, dstIP, summary, layers)
	case 1: // ICMP
		parseICMP(data, summary, layers)
	case 58: // ICMPv6
		summary.Protocol = "ICMPv6"
		if len(data) >= 2 {
			summary.Info = fmt.Sprintf("ICMPv6 Type=%d Code=%d", data[0], data[1])
		}
	default:
		summary.Protocol = fmt.Sprintf("IP/%d", proto)
		summary.Info = fmt.Sprintf("IP Protocol %d, %d bytes", proto, len(data))
	}
}

func parseTCP(data []byte, srcIP, dstIP string, summary *models.PacketSummary, layers *[]models.ProtocolLayer) {
	summary.Protocol = "TCP"
	if len(data) < 20 {
		summary.Info = "Truncated TCP segment"
		return
	}
	srcPort := binary.BigEndian.Uint16(data[0:2])
	dstPort := binary.BigEndian.Uint16(data[2:4])
	seq := binary.BigEndian.Uint32(data[4:8])
	ack := binary.BigEndian.Uint32(data[8:12])
	dataOffset := int(data[12]>>4) * 4
	if dataOffset < 20 || dataOffset > len(data) {
		dataOffset = 20
	}
	flags := data[13]
	win := binary.BigEndian.Uint16(data[14:16])

	flagNames := tcpFlagsString(flags)
	payload := data[dataOffset:]

	summary.SrcAddr = fmt.Sprintf("%s:%d", srcIP, srcPort)
	summary.DstAddr = fmt.Sprintf("%s:%d", dstIP, dstPort)
	summary.Info = fmt.Sprintf("%d → %d [%s] Seq=%d Ack=%d Win=%d Len=%d",
		srcPort, dstPort, flagNames, seq, ack, win, len(payload))

	*layers = append(*layers, models.ProtocolLayer{
		Name:    "Transmission Control Protocol (TCP)",
		Summary: fmt.Sprintf("端口 %d → %d [%s], 载荷 %d 字节", srcPort, dstPort, flagNames, len(payload)),
		Fields: []models.LayerField{
			{Key: "源端口", Value: fmt.Sprintf("%d", srcPort)},
			{Key: "目的端口", Value: fmt.Sprintf("%d", dstPort)},
			{Key: "标志位", Value: fmt.Sprintf("[%s] (0x%02x)", flagNames, flags)},
			{Key: "序列号 (Seq)", Value: fmt.Sprintf("%d", seq)},
			{Key: "确认号 (Ack)", Value: fmt.Sprintf("%d", ack)},
			{Key: "窗口大小", Value: fmt.Sprintf("%d", win)},
			{Key: "首部长度", Value: fmt.Sprintf("%d bytes", dataOffset)},
			{Key: "载荷长度", Value: fmt.Sprintf("%d bytes", len(payload))},
		},
	})

	if len(payload) > 0 {
		inspectAppLayer(srcPort, dstPort, payload, summary, layers)
	}
}

func parseUDP(data []byte, srcIP, dstIP string, summary *models.PacketSummary, layers *[]models.ProtocolLayer) {
	summary.Protocol = "UDP"
	if len(data) < 8 {
		summary.Info = "Truncated UDP datagram"
		return
	}
	srcPort := binary.BigEndian.Uint16(data[0:2])
	dstPort := binary.BigEndian.Uint16(data[2:4])
	udpLen := binary.BigEndian.Uint16(data[4:6])
	payload := data[8:]

	summary.SrcAddr = fmt.Sprintf("%s:%d", srcIP, srcPort)
	summary.DstAddr = fmt.Sprintf("%s:%d", dstIP, dstPort)
	summary.Info = fmt.Sprintf("%d → %d Len=%d", srcPort, dstPort, len(payload))

	*layers = append(*layers, models.ProtocolLayer{
		Name:    "User Datagram Protocol (UDP)",
		Summary: fmt.Sprintf("端口 %d → %d, 长度 %d", srcPort, dstPort, udpLen),
		Fields: []models.LayerField{
			{Key: "源端口", Value: fmt.Sprintf("%d", srcPort)},
			{Key: "目的端口", Value: fmt.Sprintf("%d", dstPort)},
			{Key: "数据报长度", Value: fmt.Sprintf("%d bytes", udpLen)},
			{Key: "载荷长度", Value: fmt.Sprintf("%d bytes", len(payload))},
		},
	})

	if (srcPort == 53 || dstPort == 53) && len(payload) >= 12 {
		parseDNS(payload, summary, layers)
		return
	}
	if len(payload) > 0 && isSIPPayload(srcPort, dstPort, payload) {
		parseSIP(payload, summary, layers)
	}
}

func parseICMP(data []byte, summary *models.PacketSummary, layers *[]models.ProtocolLayer) {
	summary.Protocol = "ICMP"
	if len(data) < 4 {
		summary.Info = "Truncated ICMP packet"
		return
	}
	icmpType := data[0]
	code := data[1]
	typeName := icmpTypeName(icmpType)
	summary.Info = fmt.Sprintf("%s (Type=%d, Code=%d)", typeName, icmpType, code)
	if (icmpType == 8 || icmpType == 0) && len(data) >= 8 {
		id := binary.BigEndian.Uint16(data[4:6])
		seq := binary.BigEndian.Uint16(data[6:8])
		summary.Info = fmt.Sprintf("%s id=0x%04x seq=%d", typeName, id, seq)
	}

	*layers = append(*layers, models.ProtocolLayer{
		Name:    "Internet Control Message Protocol (ICMP)",
		Summary: summary.Info,
		Fields: []models.LayerField{
			{Key: "类型 (Type)", Value: fmt.Sprintf("%d (%s)", icmpType, typeName)},
			{Key: "代码 (Code)", Value: fmt.Sprintf("%d", code)},
		},
	})
}

func icmpTypeName(t byte) string {
	switch t {
	case 0:
		return "Echo Reply (Ping 响应)"
	case 3:
		return "Destination Unreachable"
	case 8:
		return "Echo Request (Ping 请求)"
	case 11:
		return "Time Exceeded"
	default:
		return fmt.Sprintf("Type %d", t)
	}
}

func parseDNS(data []byte, summary *models.PacketSummary, layers *[]models.ProtocolLayer) {
	summary.Protocol = "DNS"
	txID := binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])
	isResp := (flags & 0x8000) != 0

	qName := parseDNSName(data, 12)
	kind := "Standard query"
	if isResp {
		kind = "Standard query response"
	}
	if qName != "" {
		summary.Info = fmt.Sprintf("%s 0x%04x %s", kind, txID, qName)
	} else {
		summary.Info = fmt.Sprintf("%s 0x%04x Q=%d A=%d", kind, txID, qdCount, anCount)
	}

	*layers = append(*layers, models.ProtocolLayer{
		Name:    "Domain Name System (DNS)",
		Summary: summary.Info,
		Fields: []models.LayerField{
			{Key: "事务 ID", Value: fmt.Sprintf("0x%04x", txID)},
			{Key: "类型", Value: kind},
			{Key: "查询域名", Value: qName},
			{Key: "问题数 / 回答数", Value: fmt.Sprintf("%d / %d", qdCount, anCount)},
		},
	})
}

func parseDNSName(data []byte, offset int) string {
	var labels []string
	for offset < len(data) {
		l := int(data[offset])
		if l == 0 {
			break
		}
		if (l & 0xc0) == 0xc0 {
			break
		}
		offset++
		if offset+l > len(data) {
			break
		}
		labels = append(labels, string(data[offset:offset+l]))
		offset += l
	}
	return strings.Join(labels, ".")
}

func inspectAppLayer(srcPort, dstPort uint16, payload []byte, summary *models.PacketSummary, layers *[]models.ProtocolLayer) {
	// SIP over TCP detection
	if isSIPPayload(srcPort, dstPort, payload) {
		parseSIP(payload, summary, layers)
		return
	}

	// HTTP detection
	s := string(payload)
	if strings.HasPrefix(s, "GET ") || strings.HasPrefix(s, "POST ") ||
		strings.HasPrefix(s, "PUT ") || strings.HasPrefix(s, "DELETE ") ||
		strings.HasPrefix(s, "HEAD ") || strings.HasPrefix(s, "OPTIONS ") ||
		strings.HasPrefix(s, "HTTP/1.") {
		summary.Protocol = "HTTP"
		firstLine := s
		if idx := strings.IndexAny(s, "\r\n"); idx > 0 {
			firstLine = s[:idx]
		}
		if len(firstLine) > 120 {
			firstLine = firstLine[:120] + "..."
		}
		summary.Info = firstLine
		*layers = append(*layers, models.ProtocolLayer{
			Name:    "Hypertext Transfer Protocol (HTTP)",
			Summary: firstLine,
			Fields: []models.LayerField{
				{Key: "首行", Value: firstLine},
				{Key: "载荷大小", Value: fmt.Sprintf("%d bytes", len(payload))},
			},
		})
		return
	}

	// TLS detection
	if len(payload) >= 5 && (payload[0] == 0x16 || payload[0] == 0x17 || payload[0] == 0x15) && payload[1] == 0x03 {
		summary.Protocol = "TLS"
		recType := "Application Data"
		switch payload[0] {
		case 0x16:
			recType = "Handshake"
			if len(payload) > 5 && payload[5] == 0x01 {
				recType = "Client Hello"
			} else if len(payload) > 5 && payload[5] == 0x02 {
				recType = "Server Hello"
			}
		case 0x15:
			recType = "Alert"
		}
		summary.Info = fmt.Sprintf("TLS %s (Len=%d)", recType, len(payload))
		*layers = append(*layers, models.ProtocolLayer{
			Name:    "Transport Layer Security (TLS)",
			Summary: summary.Info,
			Fields: []models.LayerField{
				{Key: "记录类型", Value: recType},
				{Key: "版本标识", Value: fmt.Sprintf("0x%02x%02x", payload[1], payload[2])},
				{Key: "载荷长度", Value: fmt.Sprintf("%d bytes", len(payload))},
			},
		})
		return
	}

	// SSH detection
	if srcPort == 22 || dstPort == 22 || strings.HasPrefix(s, "SSH-") {
		summary.Protocol = "SSH"
		if strings.HasPrefix(s, "SSH-") {
			line := strings.TrimSpace(strings.Split(s, "\n")[0])
			summary.Info = "Protocol: " + line
		}
		return
	}

	// DNS over TCP
	if (srcPort == 53 || dstPort == 53) && len(payload) >= 14 {
		parseDNS(payload[2:], summary, layers)
	}
}

var sipMethods = []string{
	"INVITE ", "REGISTER ", "ACK ", "BYE ", "CANCEL ", "OPTIONS ",
	"INFO ", "PRACK ", "SUBSCRIBE ", "NOTIFY ", "UPDATE ", "REFER ",
	"MESSAGE ", "PUBLISH ",
}

func isSIPPayload(srcPort, dstPort uint16, payload []byte) bool {
	if len(payload) < 8 {
		return false
	}
	s := string(payload)
	if strings.HasPrefix(s, "SIP/2.0 ") {
		return true
	}
	for _, m := range sipMethods {
		if strings.HasPrefix(s, m) && strings.Contains(s, "SIP/2.0") {
			return true
		}
	}
	// Fallback: standard SIP ports with printable text headers
	if (srcPort == 5060 || dstPort == 5060 || srcPort == 5061 || dstPort == 5061) && strings.Contains(s, "SIP/2.0") {
		return true
	}
	return false
}

func parseSIP(payload []byte, summary *models.PacketSummary, layers *[]models.ProtocolLayer) {
	summary.Protocol = "SIP"
	raw := string(payload)
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")

	firstLine := ""
	if len(lines) > 0 {
		firstLine = strings.TrimSpace(lines[0])
	}
	if firstLine == "" {
		firstLine = "SIP Message"
	}

	headerOrder := []string{"Call-ID", "From", "To", "CSeq", "Via", "Contact", "User-Agent", "Content-Type", "Content-Length"}
	foundHeaders := map[string]string{}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			break // end of SIP headers (SDP body follows)
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:colon])
		v := strings.TrimSpace(line[colon+1:])
		for _, target := range headerOrder {
			if strings.EqualFold(k, target) {
				if _, exists := foundHeaders[target]; !exists {
					foundHeaders[target] = v
				}
				break
			}
		}
	}

	info := firstLine
	if cseq, ok := foundHeaders["CSeq"]; ok && cseq != "" {
		info = fmt.Sprintf("%s  (CSeq: %s)", firstLine, cseq)
	}
	if len(info) > 130 {
		info = info[:130] + "..."
	}
	summary.Info = info

	fields := []models.LayerField{
		{Key: "起始行", Value: firstLine},
	}
	for _, target := range headerOrder {
		if v, ok := foundHeaders[target]; ok && v != "" {
			fields = append(fields, models.LayerField{Key: target, Value: v})
		}
	}
	fields = append(fields, models.LayerField{Key: "报文大小", Value: fmt.Sprintf("%d bytes", len(payload))})

	*layers = append(*layers, models.ProtocolLayer{
		Name:    "Session Initiation Protocol (SIP)",
		Summary: info,
		Fields:  fields,
	})
}

func tcpFlagsString(flags byte) string {
	var out []string
	if flags&0x02 != 0 {
		out = append(out, "SYN")
	}
	if flags&0x10 != 0 {
		out = append(out, "ACK")
	}
	if flags&0x08 != 0 {
		out = append(out, "PSH")
	}
	if flags&0x01 != 0 {
		out = append(out, "FIN")
	}
	if flags&0x04 != 0 {
		out = append(out, "RST")
	}
	if flags&0x20 != 0 {
		out = append(out, "URG")
	}
	if len(out) == 0 {
		return "NONE"
	}
	return strings.Join(out, ",")
}

func buildHexDump(data []byte) []models.HexLine {
	const width = 16
	lines := make([]models.HexLine, 0, (len(data)+width-1)/width)
	for off := 0; off < len(data); off += width {
		end := off + width
		if end > len(data) {
			end = len(data)
		}
		chunk := data[off:end]
		var hexParts []string
		var asciiBuilder strings.Builder
		for i := 0; i < width; i++ {
			if i < len(chunk) {
				b := chunk[i]
				hexParts = append(hexParts, fmt.Sprintf("%02x", b))
				if b >= 32 && b <= 126 {
					asciiBuilder.WriteByte(b)
				} else {
					asciiBuilder.WriteByte('.')
				}
			} else {
				hexParts = append(hexParts, "  ")
			}
			if i == 7 {
				hexParts = append(hexParts, "")
			}
		}
		lines = append(lines, models.HexLine{
			Offset: fmt.Sprintf("%04x", off),
			Hex:    strings.Join(hexParts, " "),
			ASCII:  asciiBuilder.String(),
		})
	}
	return lines
}
