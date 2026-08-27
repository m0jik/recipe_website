package services

// Pipeline: validate size → detect MIME -> look up codec -> resize (downscaled) ->save

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"

	"github.com/gabriel-vasile/mimetype"
	"golang.org/x/image/draw"
)

// MaxImageBytes and MaxImageWidth can be updated
const (
	MaxImageBytes = 2 << 20 // 2 MB
	MaxImageWidth = 1280
)

// ImageCodec handles reading and saving one image format (e.g. JPEG or PNG)
// Add a new format by calling RegisterCodec — no other code needs to change
type ImageCodec interface {
	// Decode reads the raw image bytes and returns an image.Image
	Decode(r io.Reader) (image.Image, error)
	// Encode writes the image to w in the target format
	Encode(w io.Writer, img image.Image) error
	// Ext returns the file extension to use, e.g. ".jpg"
	Ext() string
}

// Built-in codecs (JPEG and PNG ship out of the box)
type jpegCodec struct{}

func (jpegCodec) Decode(r io.Reader) (image.Image, error) {
	return jpeg.Decode(r)
}

func (jpegCodec) Encode(w io.Writer, img image.Image) error {
	return jpeg.Encode(w, img, &jpeg.Options{Quality: 85})
}

func (jpegCodec) Ext() string {
	return ".jpg"
}

type pngCodec struct{}

func (pngCodec) Decode(r io.Reader) (image.Image, error) {
	return png.Decode(r)
}

func (pngCodec) Encode(w io.Writer, img image.Image) error {
	return png.Encode(w, img)
}

func (pngCodec) Ext() string {
	return ".png"
}

// Codec registry

// codecs maps MIME type → codec. Pre-populated with JPEG and PNG.
// Call RegisterCodec to extend the service with additional formats.
var codecs = map[string]ImageCodec{
	"image/jpeg": jpegCodec{},
	"image/png":  pngCodec{},
}

// RegisterCodec adds (or replaces) the codec for a MIME type.
// Call this once at startup, e.g. in an init() in your webp package:

// RegisterCodec : services.RegisterCodec("image/webp", webpCodec{})
func RegisterCodec(mimeType string, c ImageCodec) {
	codecs[mimeType] = c
}

// ImageStore is the interface for persisting an image file.

// ImageStore saves images.
// LocalStore is the default; provide a different implementation by passing it to NewImageService.
type ImageStore interface {
	Save(filename string, data []byte) (string, error)
}

// LocalStore saves images to a directory on disk.
type LocalStore struct {
	Dir string
}

func (l *LocalStore) Save(filename string, data []byte) (string, error) {
	if err := os.MkdirAll(l.Dir, 0o755); err != nil {
		return "", fmt.Errorf("could not create upload dir: %w", err)
	}
	path := filepath.Join(l.Dir, filename)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("could not write file: %w", err)
	}
	return "/uploads/" + filename, nil
}

// ImageService handles image processing pipeline.
type ImageService struct {
	Store    ImageStore
	MaxBytes int64
	MaxWidth int
}

func NewImageService(store ImageStore) *ImageService {
	return &ImageService{
		Store:    store,
		MaxBytes: MaxImageBytes,
		MaxWidth: MaxImageWidth,
	}
}

// ValidateSize returns an error if the file exceeds the size limit.
func (s *ImageService) ValidateSize(size int64) error {
	if size > s.MaxBytes {
		return fmt.Errorf("file too large: max %dMB", s.MaxBytes>>20)
	}
	return nil
}

// DetectType reads the file bytes to determine the actual MIME type.
func (s *ImageService) DetectType(file multipart.File) (string, error) {
	mtype, err := mimetype.DetectReader(file)
	if err != nil {
		return "", fmt.Errorf("could not detect file type: %w", err)
	}
	return mtype.String(), nil
}

// ValidateType returns an error if no codec is registered for the MIME type.
func (s *ImageService) ValidateType(mimeType string) error {
	if _, ok := codecs[mimeType]; !ok {
		return fmt.Errorf("unsupported file type %q: register a codec to enable it", mimeType)
	}
	return nil
}

// Resize decodes the image with the registered codec, shrinks it if wider than MaxWidth then re-encodes it. Returns the encoded bytes and file extension.
func (s *ImageService) Resize(file multipart.File, mimeType string) ([]byte, string, error) {
	codec := codecs[mimeType]

	img, err := codec.Decode(file)
	if err != nil {
		return nil, "", fmt.Errorf("could not decode image: %w", err)
	}

	if bounds := img.Bounds(); bounds.Dx() > s.MaxWidth {
		ratio := float64(s.MaxWidth) / float64(bounds.Dx())
		newH := int(float64(bounds.Dy()) * ratio)
		dst := image.NewRGBA(image.Rect(0, 0, s.MaxWidth, newH))
		draw.BiLinear.Scale(dst, dst.Bounds(), img, bounds, draw.Over, nil)
		img = dst
	}

	var buf bytes.Buffer
	if err := codec.Encode(&buf, img); err != nil {
		return nil, "", fmt.Errorf("could not encode image: %w", err)
	}

	return buf.Bytes(), codec.Ext(), nil
}

// Process runs the full pipeline. Returns the public path (e.g. "/uploads/abc123.jpg")
func (s *ImageService) Process(file multipart.File, header *multipart.FileHeader) (string, error) {
	if err := s.ValidateSize(header.Size); err != nil {
		return "", err
	}

	mimeType, err := s.DetectType(file)
	if err != nil {
		return "", err
	}

	if err := s.ValidateType(mimeType); err != nil {
		return "", err
	}

	// DetectType consumed the start of the file — seek back to the beginning.
	if _, err := file.Seek(0, 0); err != nil {
		return "", fmt.Errorf("could not reset file: %w", err)
	}

	data, ext, err := s.Resize(file, mimeType)
	if err != nil {
		return "", err
	}

	filename, err := randomFilename(ext)
	if err != nil {
		return "", err
	}

	return s.Store.Save(filename, data)
}

func randomFilename(ext string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b) + ext, nil
}
