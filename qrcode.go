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

// GenerateQRcodePath generates the QR code image for the 2FA secret key.
func (m *Middleware) GenerateQRcodePath(c *fiber.Ctx) error {
	// Get the account name from c.Locals using the specified context key
	accountName, ok := c.Locals(m.Config.AccountName).(string)
	if !ok || accountName == "" {
		// If account name is not found or is an empty string, use a default value
		accountName = "gopher"
	}

	// Get the context key from the account name
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

	// Generate the QR code content
	secretKey := info.GetSecret()
	qrCodeContent := fmt.Sprintf(m.Config.QRCode.Content, m.Config.Issuer, accountName, secretKey, m.Config.Issuer)

	// Check if a custom QR code image is provided in the configuration
	if m.Config.QRCode.Image != nil {
		// Set the response headers
		c.Set(fiber.HeaderContentType, "image/png")

		// Write the custom QR code image to the response
		return png.Encode(c, m.Config.QRCode.Image)
	}

	// Generate the default QR code image
	qrCodeBytes, err := qrcode.Encode(qrCodeContent, m.Config.Encode.Level, m.Config.Encode.Size)
	if err != nil {
		return m.SendInternalErrorResponse(c, err)
	}

	// Decode the QR code bytes into an image.Image
	qrCodeImage, _, err := image.Decode(bytes.NewReader(qrCodeBytes))
	if err != nil {
		return m.SendInternalErrorResponse(c, err)
	}

	// Set the response headers
	c.Set(fiber.HeaderContentType, "image/png")

	// Write the QR code image to the response
	return png.Encode(c, qrCodeImage)
}
