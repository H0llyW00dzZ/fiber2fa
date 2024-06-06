# Fiber 2FA Middleware
[![Go Version](https://img.shields.io/badge/1.22.3-gray?style=flat&logo=go&logoWidth=15)](https://github.com/H0llyW00dzZ/fiber2fa/blob/master/go.mod#L3blob/master/go.mod#L3) [![Go Reference](https://pkg.go.dev/badge/github.com/H0llyW00dzZ/fiber2fa.svg)](https://pkg.go.dev/github.com/H0llyW00dzZ/fiber2fa) [![Go Report Card](https://goreportcard.com/badge/github.com/H0llyW00dzZ/fiber2fa)](https://goreportcard.com/report/github.com/H0llyW00dzZ/fiber2fa)

This is a custom 2FA (Two-Factor Authentication) middleware for the Fiber web framework. It provides a secure and easy-to-use solution for implementing 2FA in Fiber applications. The middleware supports both HOTP (HMAC-based One-Time Password) and TOTP (Time-based One-Time Password) authentication and offers customizable configuration options.

> [!WARNING]
> This 2FA middleware is still a work in progress and may not be stable for use in production environments (e.g., QR Code Builder), since it is rewritten from scratch with some improvements. Use it with caution and thoroughly test it before deploying to production. It is recommended to use it locally for testing purposes.


> [!NOTE]
> This 2FA project was inspired by some QR code systems in my country (e.g., https://qris.id/). However, it is built in a modern way and purely written in Go (which is more secure and can leverage the system easily), rather than the traditional way (where it is written in PHP).
> More QR code system projects might be implemented in the future (e.g., payment systems through banking similar to https://qris.id/).

## Features

The middleware provides the following features:

### HOTP Authentication (Currently implemented internally)
- Generation and verification of HOTP tokens
- Customizable token length and counter synchronization
- Automatic generation of random secrets if not provided
- Support for various hash algorithms (SHA1, SHA256, SHA512, BLAKE2b, BLAKE3)
- Configurable synchronization window for handling counter desynchronization
- Automatic counter resynchronization based on predefined thresholds
- Dynamic adjustment of synchronization window size based on counter mismatch frequency

> [!NOTE]
> Some HOTP implementations here follow the standards defined in [RFC 4226](https://tools.ietf.org/html/rfc4226). However, they are built on top of modern & advanced cryptographic knowledge and best practices, rather than using outdated or traditional approaches. This is because `Go` is considered one of the best programming languages for `cryptographic` implementations, compared to `C` or `C++`.

### TOTP Authentication
- Generation and verification of TOTP tokens
- Customizable token length and time step size
- Automatic generation of random secrets if not provided
- Support for various hash algorithms (SHA1, SHA256, SHA512, BLAKE2b, BLAKE3)
- Configurable synchronization window for handling time drift
- Automatic token expiration and cleanup

> [!NOTE]
> Some TOTP implementations here adhere to the standards defined in [RFC 6238](https://tools.ietf.org/html/rfc6238). However, they are built on top of modern & advanced cryptographic knowledge and best practices, rather than relying on outdated or traditional methods. This is because `Go` is considered one of the best programming languages for `cryptographic` implementations, compared to `C` or `C++`.

The notes effectively communicate that the HOTP and TOTP implementations follow the respective RFCs while leveraging modern and advanced cryptographic knowledge and best practices. The emphasis on Go's suitability for cryptographic implementations compared to C or C++ is also clearly stated.

### Flexible Storage
- Support for various storage providers (e.g., in-memory, MongoDB, MySQL, PostgreSQL, Redis, SQLite3)
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
- Customizable QR code path template
- Support for custom QR code images
- Customizable QR code content template
- Configurable QR code recovery level and image size

### Customizable Token Lookup
- Flexible token lookup from various sources (header, query, form, param, cookie)
- Configurable token lookup string format

### Context Key Management
- Customizable context key for storing 2FA information in the request context
- Ability to retrieve and manage context keys based on account names

### Error Handling
- Customizable error handling for unauthorized and internal server errors
- Support for various response formats (plain text, JSON, XML)

### Built-in 64-bit Integer
- Most bits and Unix timestamps are built using 64-bit integers, capable of representing dates billions of years into the future.

More features and validation capabilities will be added in the future to enhance the middleware's functionality and cater to a wider range of validation scenarios.

## Benchmark

- #### v0.3.0

```
goos: windows
goarch: amd64
pkg: github.com/H0llyW00dzZ/fiber2fa
cpu: AMD Ryzen 9 3900X 12-Core Processor            
BenchmarkJSONSonicMiddlewareWithInvalidCookie-24         	  113605	      9290 ns/op	    6065 B/op	      29 allocs/op
BenchmarkJSONSonicWithValid2FA-24                        	   55086	     21073 ns/op	    9598 B/op	      66 allocs/op
BenchmarkJSONSonicWithValidCookie-24                     	   96120	     12311 ns/op	    7399 B/op	      41 allocs/op
BenchmarkJSONStdLibraryMiddlewareWithInvalidCookie-24    	  128434	      9386 ns/op	    6003 B/op	      29 allocs/op
BenchmarkJSONStdLibraryMiddlewareWithValid2FA-24         	   49399	     24714 ns/op	    8200 B/op	      68 allocs/op
BenchmarkJSONStdLibraryWithValidCookie-24                	   60553	     20039 ns/op	    7108 B/op	      46 allocs/op
```

> [!NOTE]
> The benchmark results are based on the latest version of the middleware (v0.3.0) and were performed on a Windows machine with an AMD Ryzen 9 3900X 12-Core Processor. The results may vary depending on the system configuration and environment.
>
> The benchmark tests cover different scenarios, including:
> - Middleware performance with an invalid cookie using the Sonic JSON library
> - Middleware performance with a valid 2FA token using the Sonic JSON library
> - Middleware performance with a valid cookie using the Sonic JSON library
> - Middleware performance with an invalid cookie using the standard library JSON package
> - Middleware performance with a valid 2FA token using the standard library JSON package
> - Middleware performance with a valid cookie using the standard library JSON package
>
> The benchmark results provide insights into the performance characteristics of the middleware under different conditions and JSON libraries. It's important to consider these results when evaluating the middleware's suitability for specific use cases and performance requirements.
>
> Also note that benchmark results may be updated in the future as the middleware evolves and new versions are released.

## Contributing

Contributions are welcome! If you encounter any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [BSD License](LICENSE).
