package pcap

import (
	"testing"
	"time"

	"ssh-packet-capture/internal/models"
)

func TestParseSIP(t *testing.T) {
	sipPayload := []byte("INVITE sip:1002@10.0.0.2 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK776asdhds\r\n" +
		"From: <sip:1001@10.0.0.1>;tag=1928301774\r\n" +
		"To: <sip:1002@10.0.0.2>\r\n" +
		"Call-ID: a84b4c76e66710@10.0.0.1\r\n" +
		"CSeq: 314159 INVITE\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 0\r\n\r\n")

	if !isSIPPayload(5060, 5060, sipPayload) {
		t.Fatalf("expected isSIPPayload to return true")
	}

	summary := models.PacketSummary{No: 1, Timestamp: time.Now().Format("15:04:05.000000")}
	layers := []models.ProtocolLayer{}
	parseSIP(sipPayload, &summary, &layers)

	if summary.Protocol != "SIP" {
		t.Errorf("expected protocol SIP, got %s", summary.Protocol)
	}
	if len(layers) != 1 || layers[0].Name != "Session Initiation Protocol (SIP)" {
		t.Fatalf("unexpected SIP layers: %+v", layers)
	}
	if len(layers[0].Fields) < 6 {
		t.Errorf("expected parsed SIP headers, got %d fields", len(layers[0].Fields))
	}
}
