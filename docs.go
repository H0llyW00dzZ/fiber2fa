// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

// Package twofa provides a middleware for implementing two-factor authentication (2FA) in a Fiber application.
// It supports time-based one-time password (TOTP) authentication using the HMAC-based One-Time Password (HOTP) algorithm.
//
// # Installation
//
// To use this middleware in a Fiber project, Go must be installed and set up.
//
// 1. Install the package using Go modules:
//
//	go get github.com/H0llyW00dzZ/fiber2fa
//
// 2. Import the package in the Fiber application:
//
//	import "github.com/H0llyW00dzZ/fiber2fa"
//
// # Usage
//
// To use the 2FA middleware in a Fiber application, create a new instance of the middleware with the desired configuration and register it with the application.
//
//	package main
//
//	import (
//		"github.com/gofiber/fiber/v2"
//		"github.com/H0llyW00dzZ/fiber2fa"
//	)
//
//	func main() {
//		app := fiber.New()
//
//		app.Use(twofa.New(twofa.Config{
//			Secret:      "your-secret-key",
//			Issuer:      "MyApp",
//			AccountName: "email",
//			Storage:     storage,
//		}))
//
//		// Register routes and start the server
//		// ...
//
//		app.Listen(":3000")
//	}
//
// In the example above, a new instance of the 2FA middleware is created with a configuration that specifies the secret key, issuer name, account name field, and storage provider.
//
// # Configuration
//
// The 2FA middleware accepts a [twofa.Config] struct for configuration. The available options are:
//
//   - Secret: The shared secret used for generating and verifying TOTP tokens. This field is required.
//   - Issuer: The name of the issuer to be displayed in the authenticator app. Default is "MyApp".
//   - AccountName: The name of the account to be displayed in the authenticator app. Default is an empty string.
//   - DigitsCount: The number of digits in the generated TOTP token. Default is 6.
//   - Period: The time step size in seconds for generating TOTP tokens. Default is 30 seconds.
//   - SkipCookies: A list of paths that should skip the 2FA middleware. Default is an empty slice.
//   - CookieName: The name of the cookie used to store the 2FA validation status. Default is "twofa_cookie".
//   - CookieMaxAge: The maximum age of the 2FA cookie in seconds. Default is 86400 (24 hours).
//   - CookiePath: The path scope of the 2FA cookie. Default is "/".
//   - CookieDomain: The domain scope of the 2FA cookie. If set to "auto", it will automatically set the cookie domain based on the request's domain if HTTPS is used. Default is an empty string.
//   - CookieSecure: Determines whether the 2FA cookie should be sent only over HTTPS. Default is false.
//   - RedirectURL: The URL to redirect the user to when 2FA is required. Default is "/2fa".
//   - Storage: The storage provider for storing 2FA information. Default is nil (in-memory storage).
//   - TokenLookup: A string in the form of "<source>:<name>" that is used to extract the token from the request. Default is "query:token".
//   - ContextKey: The key used to store the 2FA information in the context. Default is an empty string.
//   - JSONMarshal: A custom JSON marshaling function. Default is json.Marshal.
//   - JSONUnmarshal: A custom JSON unmarshaling function. Default is json.Unmarshal.
//   - Next: An optional function that determines whether to skip the 2FA middleware for a given request. If the function returns true, the middleware will be skipped. Default is nil.
//   - QRCode: The configuration for the QR code generation. It allows customizing the QR code path template, image, and content. Default is [twofa.DefaultQRCodeConfig].
//   - Encode: The configuration for the QR code encoding. It allows customizing the QR code recovery level and size. Default is [twofa.DefaultEncodeConfig].
//
// # Storage Providers
//
// The 2FA middleware requires a storage provider to store the 2FA information for each user. The storage provider should implement the [fiber.Storage] interface.
//
// You can use any storage provider that implements the [fiber.Storage] interface, such as:
//
//   - [fiber.Storage]: The default in-memory storage provider.
//   - mongodb: A MongoDB storage provider.
//   - mysql: A MySQL storage provider.
//   - postgres: A PostgreSQL storage provider.
//   - redis: A Redis storage provider.
//   - sqlite3: An SQLite3 storage provider.
//
// # QR Code Generation
//
// The 2FA middleware provides a route for generating QR codes that can be scanned by authenticator apps to set up 2FA for a user.
//
// By default, the QR code generation route is accessible at "/2fa/register?account=<account_name>". You can customize the path template by modifying the PathTemplate field in the [twofa.QRCodeConfig] struct.
//
// The QR code image can be customized by providing a custom image in the Image field of the [twofa.QRCodeConfig] struct. If a custom image is provided, it will be used as the background image for the QR code.
//
// The content of the QR code can be customized by modifying the Content field in the [twofa.QRCodeConfig] struct. The default content format is "otpauth://totp/%s:%s?secret=%s&issuer=%s".
//
// # Error Handling
//
// The 2FA middleware handles errors internally and returns appropriate HTTP status codes and error messages.
//
// If an error occurs during the 2FA process, the middleware will return a response with a status code of 401 (Unauthorized) or 500 (Internal Server Error), depending on the nature of the error.
//
// The error messages are sent as plain text in the response body.
//
// # Skipping 2FA
//
// You can skip the 2FA middleware for certain routes by specifying the paths in the SkipCookies field of the [twofa.Config] struct.
//
// Additionally, you can provide a custom function in the Next field of the [twofa.Config] struct to determine whether to skip the 2FA middleware for a given request. If the function returns true, the middleware will be skipped.
package twofa
