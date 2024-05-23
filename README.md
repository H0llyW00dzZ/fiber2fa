# Fiber 2FA Middleware
[![Go Version](https://img.shields.io/badge/1.22.3-gray?style=flat&logo=go&logoWidth=15)](https://github.com/H0llyW00dzZ/fiber2fa/blob/master/go.mod#L3blob/master/go.mod#L3)

This is a custom 2FA (Two-Factor Authentication) middleware for the Fiber web framework. It provides a secure and easy-to-use solution for implementing 2FA in Fiber applications. The middleware supports TOTP (Time-based One-Time Password) authentication and offers customizable configuration options.

> [!NOTE]
> This 2FA middleware is still a work in progress and may not be stable for use in production environments. Use it with caution and thoroughly test it before deploying to production.

## Features

The middleware provides the following features:

### TOTP Authentication
- Generation and verification of TOTP tokens
- Customizable token length and time step size

### Flexible Storage
- Support for various storage providers (e.g., in-memory, database)
- Customizable storage configuration

### Cookie-based Authentication
- Secure cookie-based authentication for 2FA validation
- Customizable cookie settings (name, expiration, domain, etc.)

### Customizable Redirect
- Configurable redirect URL for 2FA validation
- Ability to skip 2FA for specific paths

### JSON Marshaling and Unmarshaling
- Customizable JSON marshaling and unmarshaling functions
- Support for custom JSON encoding/decoding

### Advanced Configuration
- Customizable context key for storing 2FA information
- Ability to skip middleware based on custom logic

### QR Code Generation
- Automatic generation of QR code images for 2FA secret keys
- Customizable barcode path template
- Support for custom barcode images

### Customizable Token Lookup
- Flexible token lookup from various sources (header, query, form, param, cookie)
- Configurable token lookup string format

### Context Key Management
- Customizable context key for storing 2FA information in the request context
- Ability to retrieve and manage context keys based on account names

More features and validation capabilities will be added in the future to enhance the middleware's functionality and cater to a wider range of validation scenarios.

## Contributing

Contributions are welcome! If you encounter any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [BSD License](LICENSE).
