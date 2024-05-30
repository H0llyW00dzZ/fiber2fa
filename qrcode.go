// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package twofa

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/skip2/go-qrcode"
)

// GenerateQRcodePath generates the QR code image for the 2FA secret key and stores the QR code data.
//
// TODO: Improve this function by using an otpverifier (internal) package.
// The QRCodePath (this function) should be the location where the user wants to scan the QR code. For example, if the user registers from example.com/2fa/register,
// then this is the place for the QR code image: example.com/2fa/register/scanqrcode/b689a842-065f-4664-xxxx-xxxxxxxxx.png (note: "b689a842-065f-4664-xxxx-xxxxxxxxx" is a UUID).
// After the user completes scanning the QR code at example.com/2fa/register, this path will redirect to another page using c.Next().
// It's possible to improve this method using the above approach without relying on or needing a filesystem such as a file manager (e.g., for storing the QR code image), since this is written in Go.
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

	// Check if the user is already registered
	if info.IsRegistered() {
		// User is already registered, skip generating the QR code
		return c.Next()
	}

	// Generate the QR code image and data
	qrCodeImage, qrCodeData, err := m.generateQRCode(c, info)
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
func (m *Middleware) generateQRCode(c *fiber.Ctx, info *Info) (image.Image, []byte, error) {
	// Get the value of the context key
	contextValue := info.ContextKey

	// Generate the identifier using the configured identifier generator
	identifier := m.GenerateIdentifier(c)

	// Generate the QR code content
	secretKey := info.GetSecret()

	// Create a slice to hold the arguments for fmt.Sprintf
	args := make([]any, 0) // zero allocation
	args = append(args, url.QueryEscape(m.Config.Issuer), url.QueryEscape(contextValue), url.QueryEscape(secretKey), url.QueryEscape(m.Config.Issuer))

	// Add additional arguments based on the placeholders in the Content template
	numPlaceholders := strings.Count(m.Config.QRCode.Content, "%")
	for i := 3; i < numPlaceholders; i++ { // Set the default starting index to 3 to avoid writing tests again for custom content.
		// Get the value for the additional argument from the request context or configuration
		argValue := c.Query(fmt.Sprintf("arg%d", i))
		args = append(args, url.QueryEscape(argValue))
	}

	// Generate the QR code content using fmt.Sprintf with the variable arguments
	qrCodeContent := fmt.Sprintf(m.Config.QRCode.Content, args...)

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

	// Set the registration status to true
	info.SetRegistered(true)

	// Set the identifier in the Info struct
	info.SetIdentifier(identifier)

	return qrCodeImage, buf.Bytes(), nil
}
