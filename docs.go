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
//			Issuer:      "MyApp",
//			ContextKey:  "email",
//			Storage:     storage,
//		}))
//
//		// Register routes and start the server
//		// ...
//
//		app.Listen(":3000")
//	}
//
// In the example above, a new instance of the 2FA middleware is created with a configuration that specifies the issuer name, context key, and storage provider.
//
// # Configuration
//
// The 2FA middleware accepts a [twofa.Config] struct for configuration. The available options are:
//
//   - Secret: The shared secret used for generating and verifying TOTP tokens. If not provided, a random secret will be generated using https://pkg.go.dev/github.com/xlzd/gotp#RandomSecret. Default is a random secret.
//   - Issuer: The name of the issuer to be displayed in the authenticator app. Default is "MyApp".
//   - AccountName: The name of the account to be displayed in the authenticator app. Deprecated: Use "ContextKey" Instead.
//   - DigitsCount: The number of digits in the generated TOTP token. Default is 6.
//   - Period: The time step size in seconds for generating TOTP tokens. Default is 30 seconds.
//   - SkipCookies: A list of paths that should skip the 2FA middleware. Default is nil.
//   - CookieName: The name of the cookie used to store the 2FA validation status. Default is "twofa_cookie".
//   - CookieMaxAge: The maximum age of the 2FA cookie in seconds. Default is 86400 (24 hours).
//   - CookiePath: The path scope of the 2FA cookie. Default is "/".
//   - CookieDomain: The domain scope of the 2FA cookie. If set to "auto", it will automatically set the cookie domain based on the request's domain if HTTPS is used. Default is an empty string.
//   - CookieSecure: Determines whether the 2FA cookie should be sent only over HTTPS. Default is false.
//   - RedirectURL: The URL to redirect the user to when 2FA is required. Default is "/2fa".
//   - Storage: The storage provider for storing 2FA information. Default is nil (in-memory storage).
//   - StorageExpiration: The duration for which the 2FA information should be stored in the storage. Default is 0 (no expiration).
//   - TokenLookup: A string in the form of "<source>:<name>" that is used to extract the token from the request. Default is "query:token".
//   - ContextKey: The key used to store the 2FA information in the context. This field is required.
//   - JSONMarshal: A custom JSON marshaling function. Default is [json.Marshal].
//   - JSONUnmarshal: A custom JSON unmarshaling function. Default is [json.Unmarshal].
//   - Next: An optional function that determines whether to skip the 2FA middleware for a given request. If the function returns true, the middleware will be skipped. Default is nil.
//   - QRCode: The configuration for the QR code generation. It allows customizing the QR code path template, image, and content. Default is [twofa.DefaultQRCodeConfig].
//   - Encode: The configuration for the QR code encoding. It allows customizing the QR code recovery level and size. Default is [twofa.DefaultEncodeConfig].
//   - ResponseMIME: The MIME type for the response format. Default is [fiber.MIMETextPlainCharsetUTF8]. Possible values are:
//   - [fiber.MIMETextPlainCharsetUTF8] (default)
//   - [fiber.MIMEApplicationJSON]
//   - [fiber.MIMEApplicationJSONCharsetUTF8]
//   - [fiber.MIMEApplicationXML]
//   - [fiber.MIMEApplicationXMLCharsetUTF8]
//   - [fiber.MIMETextPlain]
//   - [fiber.MIMETextHTML] (custom handler required)
//   - [fiber.MIMETextHTMLCharsetUTF8] (custom handler required)
//   - [fiber.MIMETextJavaScript] (custom handler required)
//   - [fiber.MIMETextJavaScriptCharsetUTF8] (custom handler required)
//   - [fiber.MIMEApplicationForm] (custom handler required)
//   - [fiber.MIMEMultipartForm] (custom handler required)
//   - [fiber.MIMEOctetStream] (custom handler required)
//   - UnauthorizedHandler: A custom handler for unauthorized responses. Default is nil.
//   - InternalErrorHandler: A custom handler for internal server error responses. Default is nil.
//   - IdentifierGenerator: A function that generates a unique identifier for the 2FA registration. Default is nil (uses fiber utils.UUIDv4 generator).
//
// # Storage Providers
//
// The 2FA middleware requires a storage provider to store the 2FA information for each user. The storage provider should implement the [fiber.Storage] interface.
//
// You can use any storage provider that implements the [fiber.Storage] interface, such as:
//
//   - [fiber.Storage]: The default in-memory storage provider.
//   - [github.com/gofiber/storage/mongodb]: A MongoDB storage provider.
//   - [github.com/gofiber/storage/mysql]: A MySQL storage provider.
//   - [github.com/gofiber/storage/postgres]: A PostgreSQL storage provider.
//   - [github.com/gofiber/storage/redis]: A Redis storage provider.
//   - [github.com/gofiber/storage/sqlite3]: An SQLite3 storage provider.
//
// The 2FA information is stored in the storage using the ContextKey as the unique identifier. The ContextKey is bound to the raw value (2FA information) in the storage.
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
// # Custom QR Code Image Generation (Advanced use cases)
//
// The 2FA middleware allows generating custom QR code images for use with custom mobile apps or physical devices. This feature provides flexibility in integrating 2FA with custom cryptography and scanning mechanisms.
//
// To generate a custom QR code image, provide a custom image in the Image field of the [twofa.QRCodeConfig] struct. The custom image should be of type [image.Image].
//
// When a custom image is provided, the middleware will generate a QR code and overlay it on top of the custom image. The resulting QR code image can be scanned by a custom mobile app or physical device that supports QR code scanning.
//
// By using a custom QR code image, it's possible to incorporate custom branding, design, or additional information into the QR code. This allows creating a seamless and integrated 2FA experience for users.
//
// Additionally, custom cryptography techniques can be leveraged to secure the QR code data. Instead of using the default TOTP algorithm, custom encryption and decryption mechanisms can be implemented to protect the shared secret and other sensitive information embedded in the QR code.
//
// Furthermore, the custom QR code image generation feature enables extending 2FA beyond mobile apps. The QR code can be bound to physical devices or objects that have scanning capabilities, such as smart cards, badges, or dedicated hardware tokens. This provides an additional layer of security and convenience for users who prefer physical authentication methods.
//
// To implement custom QR code image generation, follow these steps:
//
//  1. Create a custom image of type [image.Image] that will serve as the background for the QR code.
//  2. Set the custom image in the Image field of the [twofa.QRCodeConfig] struct when configuring the 2FA middleware.
//  3. Implement a custom mobile app or physical device that can scan the custom QR code image and extract the necessary information for 2FA.
//  4. Optionally, implement custom cryptography techniques to secure the QR code data and ensure the integrity and confidentiality of the shared secret.
//
// By leveraging custom QR code image generation, it's possible to create a unique and secure 2FA experience tailored to specific requirements and user preferences.
//
// # Error Handling
//
// The 2FA middleware handles errors internally and returns appropriate HTTP status codes and error messages.
//
// If an error occurs during the 2FA process, the middleware will return a response with a status code of 401 (Unauthorized) or 500 (Internal Server Error), depending on the nature of the error.
//
// The error messages are sent in the specified response format (MIME type) configured in the ResponseMIME field of the [twofa.Config] struct. The default response format is plain text ([fiber.MIMETextPlainCharsetUTF8]).
//
// You can customize the error handling by providing custom handlers for unauthorized and internal server errors using the UnauthorizedHandler and InternalErrorHandler fields in the [twofa.Config] struct.
//
// # Error Variables
//
// The 2FA middleware defines several error variables that represent different types of errors that can occur during the 2FA process. These error variables are:
//
//   - [twofa.ErrorFailedToRetrieveInfo]: Indicates a failure to retrieve 2FA information from the storage.
//   - [twofa.ErrorFailedToUnmarshalInfo]: Indicates a failure to unmarshal the 2FA information.
//   - [twofa.ErrorFailedToMarshalInfo]: Indicates a failure to marshal the updated 2FA information.
//   - [twofa.ErrorFailedToStoreInfo]: Indicates a failure to store the updated 2FA information.
//   - [twofa.ErrorFailedToDeleteInfo]: Indicates a failure to delete the 2FA information.
//   - [twofa.ErrorFailedToResetStorage]: Indicates a failure to reset the storage.
//   - [twofa.ErrorFailedToCloseStorage]: Indicates a failure to close the storage.
//   - [twofa.ErrorContextKeyNotSet]: Indicates that the ContextKey is not set in the configuration.
//   - [twofa.ErrorFailedToRetrieveContextKey]: Indicates a failure to retrieve the context key from the request.
//
// These error variables are used by the middleware to provide meaningful error messages when errors occur during the 2FA process.
//
// # Skipping 2FA
//
// You can skip the 2FA middleware for certain routes by specifying the paths in the SkipCookies field of the [twofa.Config] struct.
//
// Additionally, you can provide a custom function in the Next field of the [twofa.Config] struct to determine whether to skip the 2FA middleware for a given request. If the function returns true, the middleware will be skipped.
//
// # Info Management
//
// The 2FA middleware uses the [twofa.Info] struct to manage the 2FA information for each user. The [twofa.Info] struct implements the [twofa.InfoManager] interface, which defines methods for accessing and modifying the 2FA information.
//
// The [twofa.Info] struct contains the following fields:
//
//   - [twofa.Config.ContextKey]: The context key associated with the 2FA information.
//   - [twofa.Config.Secret]: The secret used for generating and verifying TOTP tokens.
//   - [twofa.Config.CookieValue]: The value of the 2FA cookie.
//   - [twofa.Config.ExpirationTime]: The expiration time of the 2FA cookie.
//   - [twofa.Config.Registered]: The registration status of the user.
//   - [twofa.Config.Identifier]: The identifier associated with the user.
//   - [twofa.Config.QRCodeData]: The QR code data for the user.
//
// The [twofa.InfoManager] interface provides methods for accessing and modifying these fields.
//
// # Cookie Management
//
// The 2FA middleware uses cookies to store the 2FA validation status for each user. The cookie-related configurations can be customized using the following fields in the [twofa.Config] struct:
//
//   - CookieName: The name of the cookie used to store the 2FA validation status.
//   - CookieMaxAge: The maximum age of the 2FA cookie in seconds.
//   - CookiePath: The path scope of the 2FA cookie.
//   - CookieDomain: The domain scope of the 2FA cookie. If set to "auto", it will automatically set the cookie domain based on the request's domain if HTTPS is used.
//   - CookieSecure: Determines whether the 2FA cookie should be sent only over HTTPS.
//
// The middleware generates a signed cookie value using HMAC to ensure the integrity of the cookie. The cookie value contains the expiration time of the cookie.
//
// # Token Verification
//
// The 2FA middleware verifies the TOTP token provided by the user during the 2FA process. The token can be extracted from various sources such as query parameters, form data, cookies, headers, or URL parameters.
//
// The token lookup configuration is specified using the TokenLookup field in the [twofa.Config] struct. It follows the format "<source>:<name>", where <source> can be "query", "form", "cookie", "header", or "param", and <name> is the name of the parameter or key.
//
// If a valid token is provided, the middleware sets a 2FA cookie to indicate that the user has successfully completed the 2FA process. The cookie value is generated using the [twofa.Middleware.GenerateCookieValue] function, which signs the cookie value using HMAC.
//
// # Identifier Generation
//
// The 2FA middleware generates a unique identifier for each 2FA registration. The identifier is used to associate the 2FA information with a specific user or account.
//
// By default, the middleware uses the [github.com/gofiber/utils.UUIDv4] function to generate a random UUID as the identifier.
//
// The identifier generation can be customized by providing a custom function in the IdentifierGenerator field of the [twofa.Config] struct. The custom function should take a [*fiber.Ctx] as a parameter and return a string identifier.
//
// The generated identifier is stored in the [twofa.Info] struct and can be accessed using the [twofa.Info.GetIdentifier] method.
//
//	 	// Example of a custom identifier generator function.
//		func customIdentifierGenerator(c *fiber.Ctx) string {
//			// Generate a custom identifier based on the request context
//			identifier := // Custom logic to generate the identifier
//			return identifier
//		}
//
//		app.Use(twofa.New(twofa.Config{
//			Issuer:              "MyApp",
//			ContextKey:          "email",
//			Storage:             storage,
//			IdentifierGenerator: customIdentifierGenerator,
//		}))
//
// In the example above, the customIdentifierGenerator function is provided as the value for the IdentifierGenerator field in the [twofa.Config] struct. This function will be called by the middleware to generate the identifier for each 2FA registration.
//
// The custom identifier generator function can access the request context through the [*fiber.Ctx] parameter and generate the identifier based on any relevant information available in the context, such as user ID, email, or any other unique attribute.
//
// Providing a custom identifier generator allows for the flexibility to generate identifiers that are specific to the application's requirements and ensures uniqueness and compatibility with the existing user or account management system.
//
// Note: If the IdentifierGenerator field is not provided or set to nil, the middleware will use the default identifier generator, which generates a random UUID using [github.com/gofiber/utils.UUIDv4].
package twofa
