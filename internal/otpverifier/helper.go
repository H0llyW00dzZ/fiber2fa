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

// generateQRImage creates the QR code image from the OTP URL.
func generateQRImage(otpURL string, config QRCodeConfig) (image.Image, error) {
	qrCodeBytes, err := qrcode.Encode(otpURL, config.Level, config.Size)
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
func fillBackground(img *image.RGBA, backgroundColor color.Color) {
	if backgroundColor == nil {
		backgroundColor = color.White
	}
	draw.Draw(img, img.Bounds(), &image.Uniform{C: backgroundColor}, image.Point{}, draw.Src)
}

// drawTextOnImage draws text on the image at the specified position.
func drawTextOnImage(img *image.RGBA, text string, position image.Point, foregroundColor color.Color, font font.Face) {
	if text == "" || font == nil {
		return // No text or font provided, skip drawing
	}

	if foregroundColor == nil {
		foregroundColor = color.Black
	}

	drawText(img, text, position.X, position.Y, foregroundColor, font)
}

// encodeImageToPNGBytes encodes the image to PNG format and returns the bytes.
func encodeImageToPNGBytes(img *image.RGBA) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// drawText draws centered text on the image at the specified position using the provided font face.
func drawText(img *image.RGBA, text string, x, y int, color color.Color, face font.Face) {
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
func prepareImageCanvas(qrCodeImage image.Image, config QRCodeConfig) *image.RGBA {
	textHeight := 20 // This should be dynamic based on actual font size
	newWidth := config.Size
	newHeight := config.Size + 2*textHeight
	newImage := image.NewRGBA(image.Rect(0, 0, newWidth, newHeight))

	fillBackground(newImage, config.BackgroundColor)

	// Draw the QR code image onto the new image
	qrCodeBounds := image.Rect(0, textHeight, config.Size, textHeight+config.Size)
	draw.Draw(newImage, qrCodeBounds, qrCodeImage, image.Point{}, draw.Over)

	return newImage
}
