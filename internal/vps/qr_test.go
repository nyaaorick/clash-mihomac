package vps

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"
)

func TestQRRoundTripAndImport(t *testing.T) {
	link := VlessRealityLink("tokyo", "203.0.113.5", 443, "11111111-2222-3333-4444-555555555555", "PUBKEY", "ab12cd34", "www.microsoft.com")
	data, err := QRPNG(link, 512)
	if err != nil {
		t.Fatal(err)
	}
	text, err := DecodeQR(data)
	if err != nil || text != link {
		t.Fatalf("decoded %q, %v", text, err)
	}
	if n, err := ParseLink(text); err != nil || n.Name != "tokyo" {
		t.Errorf("imported %+v, %v", n, err)
	}

	// The same code as a JPEG, base64-wrapped in a data URL.
	img, _ := png.Decode(bytes.NewReader(data))
	var jb bytes.Buffer
	if err := jpeg.Encode(&jb, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	raw, err := DataURLBytes("data:image/jpeg;base64," + b64(jb.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if text, err := DecodeQR(raw); err != nil || text != link {
		t.Errorf("jpeg decode = %q, %v", text, err)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func TestDecodeQRRejectsNonCodes(t *testing.T) {
	blank := image.NewGray(image.Rect(0, 0, 200, 200))
	var buf bytes.Buffer
	png.Encode(&buf, blank)
	if _, err := DecodeQR(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "no QR code") {
		t.Errorf("blank image: %v", err)
	}
	if _, err := DecodeQR([]byte("not an image")); err == nil {
		t.Error("garbage accepted")
	}
	if _, err := DecodeQR(make([]byte, maxImageBytes+1)); err == nil {
		t.Error("oversized image accepted")
	}
	if _, err := DataURLBytes("data:image/png;base64,!!!"); err == nil {
		t.Error("bad base64 accepted")
	}
}

func TestSubscriptionRoundTrip(t *testing.T) {
	sub := Subscription("trojan://a@h1.example.com:443#one", "trojan://b@h2.example.com:443#two")
	nodes, errs := ParseSubscription([]byte(sub))
	if len(nodes) != 2 || len(errs) != 0 || nodes[1].Name != "two" {
		t.Errorf("nodes = %+v, errs = %v", nodes, errs)
	}
}
