package vps

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg" // QR images are often JPEGs
	_ "image/png"
	"strings"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	qrenc "github.com/skip2/go-qrcode"
)

// maxImageBytes bounds an uploaded QR image.
const maxImageBytes = 8 << 20

// QRPNG renders text as a QR code PNG.
func QRPNG(text string, size int) ([]byte, error) {
	if size < 128 {
		size = 256
	}
	return qrenc.Encode(text, qrenc.Medium, size)
}

// DecodeQR reads the text of a QR code from a PNG or JPEG image.
func DecodeQR(img []byte) (string, error) {
	if len(img) > maxImageBytes {
		return "", errors.New("the image is too large")
	}
	m, _, err := image.Decode(bytes.NewReader(img))
	if err != nil {
		return "", fmt.Errorf("couldn't read the image (use a PNG or JPEG): %w", err)
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(m)
	if err != nil {
		return "", err
	}
	res, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		return "", errors.New("no QR code was found in the image")
	}
	return res.GetText(), nil
}

// DataURLBytes decodes a data: URL (as a browser file reader produces) or
// bare base64.
func DataURLBytes(s string) ([]byte, error) {
	if i := strings.Index(s, ","); strings.HasPrefix(s, "data:") && i >= 0 {
		s = s[i+1:]
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("the image isn't valid base64")
	}
	return b, nil
}

// Subscription encodes share links the way subscription clients expect:
// base64 of the links, one per line.
func Subscription(links ...string) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n") + "\n"))
}
