// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package otpverifier

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"

	"github.com/skip2/go-qrcode"
	"golang.org/x/image/font"
	"golang.org/x/image/math/fixed"
)

// GenerateQRCodeImage generates a QR code image based on the provided OTP URL and configuration.
//
// TODO: Implement the following features:
//
//   - Allow placing a logo in the middle of the QR code
//   - Customize the theme (e.g., changing color, layout) beyond the default QR code system
//
// Note: These features require additional implementation and may involve modifying the QRCodeConfig struct and the GenerateQRCodeImage function.
func (qr *QRCodeConfig) GenerateQRCodeImage(otpURL string) (image.Image, error) {
	qrCodeImage, err := qr.generateQRImage(otpURL)
	if err != nil {
		return nil, err
	}

	// Create a new image with space for text above and below the QR code
	newImage := qr.prepareImageCanvas(qrCodeImage)

	// Draw the top and bottom text using the drawTextOnImage function
	qr.drawTextOnImage(newImage, qr.TopText, qr.TopTextPosition, qr.ForegroundColor, qr.Font)
	qr.drawTextOnImage(newImage, qr.BottomText, qr.BottomTextPosition, qr.ForegroundColor, qr.Font)

	return newImage, nil
}

// generateQRImage creates the QR code image from the OTP URL.
func (qr *QRCodeConfig) generateQRImage(otpURL string) (image.Image, error) {
	qrCodeBytes, err := qrcode.Encode(otpURL, qr.Level, qr.Size)
	if err != nil {
		return nil, err
	}

	qrCodeImage, _, err := image.Decode(bytes.NewReader(qrCodeBytes))
	if err != nil {
		return nil, err
	}

	return qrCodeImage, nil
}

// fillBackground fills the background of the image with the specified color.
func (qr *QRCodeConfig) fillBackground(img *image.RGBA, backgroundColor color.Color) {
	if backgroundColor == nil {
		backgroundColor = color.White
	}
	draw.Draw(img, img.Bounds(), &image.Uniform{C: backgroundColor}, image.Point{}, draw.Src)
}

// drawTextOnImage draws text on the image at the specified position.
func (qr *QRCodeConfig) drawTextOnImage(img *image.RGBA, text string, position image.Point, foregroundColor color.Color, font font.Face) {
	if text == "" || font == nil {
		return // No text or font provided, skip drawing
	}

	if foregroundColor == nil {
		foregroundColor = color.Black
	}

	qr.drawText(img, text, position.X, position.Y, foregroundColor, font)
}

// encodeImageToPNGBytes encodes the image to PNG format and returns the bytes.
func (qr *QRCodeConfig) encodeImageToPNGBytes(img *image.RGBA) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// drawText draws centered text on the image at the specified position using the provided font face.
func (qr *QRCodeConfig) drawText(img *image.RGBA, text string, x, y int, color color.Color, face font.Face) {
	drawer := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(color),
		Face: face,
	}

	textWidth := drawer.MeasureString(text).Round()
	textHeight := drawer.Face.Metrics().Height.Round()

	drawer.Dot = fixed.P(x-textWidth/2, y+textHeight/2)
	drawer.DrawString(text)
}

// prepareImageCanvas creates a new RGBA image with space for text above and below the QR code.
func (qr *QRCodeConfig) prepareImageCanvas(qrCodeImage image.Image) *image.RGBA {
	textHeight := 20 // This should be dynamic based on actual font size
	newWidth := qr.Size
	newHeight := qr.Size + 2*textHeight
	newImage := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))

	qr.fillBackground(newImage, qr.BackgroundColor)

	// Draw the QR code image onto the new image
	qrCodeBounds := image.Rect(0, textHeight, qr.Size, textHeight+qr.Size)
	draw.Draw(newImage, qrCodeBounds, qrCodeImage, image.Point{}, draw.Over)

	return newImage
}
