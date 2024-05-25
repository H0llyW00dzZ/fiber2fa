// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package twofa

import (
	"bytes"
	"fmt"
	"image"
	"image/png"

	"github.com/gofiber/fiber/v2"
	"github.com/skip2/go-qrcode"
)

// GenerateQRcodePath generates the QR code image for the 2FA secret key and stores the QR code data.
func (m *Middleware) GenerateQRcodePath(c *fiber.Ctx) error {
	// Get the context key from c.Locals
	contextKey, err := m.getContextKey(c)
	if err != nil {
		return m.SendUnauthorizedResponse(c, err)
	}

	// Retrieve the 2FA information from the storage
	info, err := m.getInfoFromStorage(contextKey)
	if err != nil {
		return m.SendInternalErrorResponse(c, err)
	}
	if info == nil {
		return m.SendUnauthorizedResponse(c, fiber.NewError(fiber.StatusUnauthorized, "2FA information not found"))
	}

	// Generate the QR code image and data
	qrCodeImage, qrCodeData, err := m.generateQRCode(info)
	if err != nil {
		return m.SendInternalErrorResponse(c, err)
	}

	// Set the QR code data in the Info struct
	info.SetQRCodeData(qrCodeData)

	// Update the Info struct in the storage
	err = m.updateInfoInStorage(contextKey)
	if err != nil {
		return m.SendInternalErrorResponse(c, err)
	}

	// Set the response headers
	c.Set(fiber.HeaderContentType, "image/png")

	// Write the QR code image to the response
	err = png.Encode(c, qrCodeImage)
	if err != nil {
		return m.SendInternalErrorResponse(c, err)
	}

	return nil
}

// generateQRCode generates the QR code image and data based on the provided Info struct.
func (m *Middleware) generateQRCode(info *Info) (image.Image, []byte, error) {
	// Get the value of the context key
	contextValue := info.ContextKey

	// Generate the QR code content
	secretKey := info.GetSecret()
	qrCodeContent := fmt.Sprintf(m.Config.QRCode.Content, m.Config.Issuer, contextValue, secretKey, m.Config.Issuer)

	// Check if a custom QR code image is provided in the configuration
	if m.Config.QRCode.Image != nil {
		// Encode the custom QR code image to PNG format
		var buf bytes.Buffer
		err := png.Encode(&buf, m.Config.QRCode.Image)
		if err != nil {
			return nil, nil, err
		}
		return m.Config.QRCode.Image, buf.Bytes(), nil
	}

	// Generate the QR code
	var qrCode *qrcode.QRCode
	var err error

	if m.Config.Encode.VersionNumber != 0 {
		// Generate the QR code with the specified version number
		qrCode, err = qrcode.NewWithForcedVersion(qrCodeContent, m.Config.Encode.VersionNumber, m.Config.Encode.Level)
	} else {
		// Generate the QR code with automatic version determination
		qrCode, err = qrcode.New(qrCodeContent, m.Config.Encode.Level)
	}

	if err != nil {
		return nil, nil, err
	}

	// Encode the QR code as PNG
	qrCodeImage := qrCode.Image(m.Config.Encode.Size)

	// Encode the QR code image to PNG format
	var buf bytes.Buffer
	err = png.Encode(&buf, qrCodeImage)
	if err != nil {
		return nil, nil, err
	}

	return qrCodeImage, buf.Bytes(), nil
}
