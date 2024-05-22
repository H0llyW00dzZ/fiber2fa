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

// GenerateBarcodePath generates the QR code image for the 2FA secret key.
func (m *Middleware) GenerateBarcodePath(c *fiber.Ctx) error {
	// Get the account name from c.Locals using the specified context key
	accountName, ok := c.Locals(m.Config.ContextKey).(string)
	if !ok {
		// If account name is not found, use a default value or return an error
		accountName = "gopher"
	}

	// Get the context key from the account name
	contextKey, err := m.getContextKey(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString(err.Error())
	}

	// Retrieve the 2FA information from the storage
	info, err := m.getInfoFromStorage(contextKey)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}
	if info == nil {
		return c.Status(fiber.StatusUnauthorized).SendString("2FA information not found")
	}

	// Generate the QR code content
	secretKey := info.GetSecret()
	qrCodeContent := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", m.Config.Issuer, accountName, secretKey, m.Config.Issuer)

	// Check if a custom barcode image is provided in the configuration
	if m.Config.BarcodeImage != nil {
		// Set the response headers
		c.Set(fiber.HeaderContentType, "image/png")

		// Write the custom barcode image to the response
		return png.Encode(c, m.Config.BarcodeImage)
	}

	// Generate the default QR code image
	qrCodeBytes, err := qrcode.Encode(qrCodeContent, qrcode.Medium, 256)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	// Decode the QR code bytes into an image.Image
	qrCodeImage, _, err := image.Decode(bytes.NewReader(qrCodeBytes))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	// Set the response headers
	c.Set(fiber.HeaderContentType, "image/png")

	// Write the QR code image to the response
	return png.Encode(c, qrCodeImage)
}
