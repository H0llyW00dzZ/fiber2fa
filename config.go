// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package twofa

import (
	"encoding/json"
	"image"

	"github.com/gofiber/fiber/v2"
	"github.com/skip2/go-qrcode"
)

// Config defines the configuration options for the 2FA middleware.
type Config struct {
	// Secret is the shared secret used for generating and verifying TOTP tokens.
	//
	// Required.
	Secret string

	// Issuer is the name of the issuer to be displayed in the authenticator app.
	//
	// Optional. Default: "MyApp"
	Issuer string

	// AccountName is the name of the account to be displayed in the authenticator app.
	//
	// Optional. Default: ""
	AccountName string

	// DigitsCount is the number of digits in the generated TOTP token.
	//
	// Optional. Default: 6
	DigitsCount int

	// Period is the time step size in seconds for generating TOTP tokens.
	//
	// Optional. Default: 30
	Period int

	// SkipCookies is a list of paths that should skip the 2FA middleware.
	//
	// Optional. Default: []string{}
	SkipCookies []string

	// CookieName is the name of the cookie used to store the 2FA validation status.
	//
	// Optional. Default: "twofa_cookie"
	CookieName string

	// CookieMaxAge is the maximum age of the 2FA cookie in seconds.
	//
	// Optional. Default: 86400 (24 hours)
	CookieMaxAge int

	// CookiePath is the path scope of the 2FA cookie.
	//
	// Optional. Default: "/"
	CookiePath string

	// CookieDomain is the domain scope of the 2FA cookie.
	//
	// If set to "auto", it will automatically set the cookie domain based on the request's domain if HTTPS is used.
	//
	// Optional. Default: ""
	CookieDomain string

	// CookieSecure determines whether the 2FA cookie should be sent only over HTTPS.
	//
	// Optional. Default: false
	CookieSecure bool

	// RedirectURL is the URL to redirect the user to when 2FA is required.
	//
	// Optional. Default: "/2fa"
	RedirectURL string

	// Storage is the storage provider for storing 2FA information.
	//
	// Optional. Default: nil (in-memory storage)
	Storage fiber.Storage

	// TokenLookup is a string in the form of "<source>:<name>" that is used to extract the token from the request.
	//
	// Optional. Default value "query:token".
	//
	// Possible values:
	//
	//  - "header:<name>"
	//  - "query:<name>"
	//  - "form:<name>"
	//  - "param:<name>"
	//  - "cookie:<name>"
	TokenLookup string

	// ContextKey is the key used to store the 2FA information in the context.
	//
	// Required.
	ContextKey string

	// JSONMarshal is a custom JSON marshaling function.
	//
	// Optional. Default: json.Marshal
	JSONMarshal JSONMarshal

	// JSONUnmarshal is a custom JSON unmarshaling function.
	//
	// Optional. Default: json.Unmarshal
	JSONUnmarshal JSONUnmarshal

	// Next defines a function to skip this middleware when returned true.
	//
	// Optional. Default: nil
	Next func(c *fiber.Ctx) bool

	// QRcodeImage is the custom barcode image to be used instead of the default QR code.
	//
	// Deprecated: replaced by "QRCode"
	QRcodeImage image.Image

	// QRCode is the configuration for the QR code generation.
	// It allows customizing the QR code path template, image, and content.
	//
	// Optional. Default: see DefaultQRCodeConfig
	QRCode QRCodeConfig

	// Encode is the configuration for the QR code encoding.
	//
	// Optional. Default: see DefaultEncodeConfig
	Encode EncodeConfig

	// ResponseMIME is the MIME type for the response format.
	//
	// Optional. Default: fiber.MIMETextPlainCharsetUTF8
	//
	// Possible values:
	//  - fiber.MIMETextPlainCharsetUTF8 (default)
	//  - fiber.MIMEApplicationJSON
	//  - fiber.MIMEApplicationJSONCharsetUTF8
	//  - fiber.MIMEApplicationXML
	//  - fiber.MIMEApplicationXMLCharsetUTF8
	ResponseMIME string

	// UnauthorizedHandler is a custom handler for unauthorized responses.
	//
	// Optional. Default: nil
	UnauthorizedHandler fiber.ErrorHandler

	// InternalErrorHandler is a custom handler for internal server error responses.
	//
	// Optional. Default: nil
	InternalErrorHandler fiber.ErrorHandler
}

// DefaultConfig  holds the default configuration values.
var DefaultConfig = Config{
	Secret:               "",
	Issuer:               "MyApp",
	AccountName:          "",
	DigitsCount:          6,
	Period:               30,
	SkipCookies:          []string{},
	CookieName:           "twofa_cookie",
	CookieMaxAge:         86400,
	CookiePath:           "/",
	CookieDomain:         "",
	CookieSecure:         false,
	RedirectURL:          "/2fa",
	Storage:              nil,
	TokenLookup:          "query:token",
	ContextKey:           "",
	JSONMarshal:          json.Marshal,
	JSONUnmarshal:        json.Unmarshal,
	Next:                 nil,
	QRCode:               DefaultQRCodeConfig,
	Encode:               DefaultEncodeConfig,
	ResponseMIME:         fiber.MIMETextPlainCharsetUTF8,
	UnauthorizedHandler:  nil,
	InternalErrorHandler: nil,
}

// JSONMarshal defines the function signature for a JSON marshal.
type JSONMarshal func(v any) ([]byte, error)

// JSONUnmarshal defines the function signature for a JSON unmarshal.
type JSONUnmarshal func(data []byte, v any) error

// QRCodeConfig defines the configuration options for the QR code generation.
type QRCodeConfig struct {
	// PathTemplate is the template for the QR code path.
	//
	// Optional. Default: "/2fa/register?account=%s"
	PathTemplate string

	// Image is the custom QR code image to be used instead of the default QR code.
	//
	// Optional. Default: nil
	Image image.Image

	// Content is the template for the QR code content.
	//
	// Optional. Default: "otpauth://totp/%s:%s?secret=%s&issuer=%s"
	Content string
}

// DefaultQRCodeConfig holds the default configuration values for the QR code generation.
var DefaultQRCodeConfig = QRCodeConfig{
	Image:   nil,
	Content: "otpauth://totp/%s:%s?secret=%s&issuer=%s",
	// TODO: Implement a page for generating a QR code that can be scanned by mobile apps to register and store the one-time password.
	// Implementation will be done later as I currently don't have a clear idea during a break.
	PathTemplate: "/2fa/register?account=%s",
}

// EncodeConfig defines the configuration options for the QR code encoding.
type EncodeConfig struct {
	// Level is the QR code recovery level.
	//
	// Optional. Default: qrcode.Medium
	Level qrcode.RecoveryLevel

	// Size is the size of the QR code image.
	//
	// Optional. Default: 256
	Size int
}

// DefaultEncodeConfig holds the default configuration values for the QR code encoding.
var DefaultEncodeConfig = EncodeConfig{
	Level: qrcode.Medium,
	Size:  256,
}
