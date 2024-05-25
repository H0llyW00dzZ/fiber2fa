// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package twofa_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	twofa "github.com/H0llyW00dzZ/fiber2fa"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/storage/memory/v2"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
)

// TestInfo_GetSecret tests the GetSecret method of the Info struct.
func TestInfo_GetSecret(t *testing.T) {
	secret := gotp.RandomSecret(16)
	info := twofa.Info{
		Secret: secret,
	}

	if got := info.GetSecret(); got != secret {
		t.Errorf("Info.GetSecret() = %v, want %v", got, secret)
	}
}

// TestInfo_GetSetCookieValue tests the GetCookieValue and SetCookieValue methods of the Info struct.
func TestInfo_GetSetCookieValue(t *testing.T) {
	cookieValue := "cookie_value"
	info := twofa.Info{}
	info.SetCookieValue(cookieValue)

	if got := info.GetCookieValue(); got != cookieValue {
		t.Errorf("Info.GetCookieValue() = %v, want %v", got, cookieValue)
	}
}

// TestInfo_GetSetExpirationTime tests the GetExpirationTime and SetExpirationTime methods of the Info struct.
func TestInfo_GetSetExpirationTime(t *testing.T) {
	expirationTime := time.Now().Add(24 * time.Hour)
	info := twofa.Info{}
	info.SetExpirationTime(expirationTime)

	if got := info.GetExpirationTime(); !got.Equal(expirationTime) {
		t.Errorf("Info.GetExpirationTime() = %v, want %v", got, expirationTime)
	}
}

// TestInfo_IsSetRegistered tests the IsRegistered and SetRegistered methods of the Info struct.
func TestInfo_IsSetRegistered(t *testing.T) {
	info := twofa.Info{}

	// Test initial registration status
	if info.IsRegistered() {
		t.Error("Info.IsRegistered() = true, want false")
	}

	// Set registration status to true
	info.SetRegistered(true)
	if !info.IsRegistered() {
		t.Error("Info.IsRegistered() = false, want true")
	}

	// Set registration status back to false
	info.SetRegistered(false)
	if info.IsRegistered() {
		t.Error("Info.IsRegistered() = true, want false")
	}
}

// TestInfo_SetContextKey tests the SetContextKey method of the Info struct.
func TestInfo_SetContextKey(t *testing.T) {
	info := twofa.Info{}
	contextKey := "user_id"

	info.SetContextKey(contextKey)

	if info.ContextKey != contextKey {
		t.Errorf("Info.ContextKey = %v, want %v", info.ContextKey, contextKey)
	}
}

// TestInfo_SetSecret tests the SetSecret method of the Info struct.
func TestInfo_SetSecret(t *testing.T) {
	info := twofa.Info{}
	secret := gotp.RandomSecret(16)

	info.SetSecret(secret)

	if info.Secret != secret {
		t.Errorf("Info.Secret = %v, want %v", info.Secret, secret)
	}
}

func TestMiddleware_Handle(t *testing.T) {
	// Set up the storage with an in-memory store for simplicity
	store := memory.New()
	secret := gotp.RandomSecret(16)

	// Create a default Info struct and store it for Simulate State
	info := twofa.Info{
		ContextKey:     "user123",
		Secret:         secret,
		CookieValue:    "",
		ExpirationTime: time.Time{},
	}
	infoJSON, _ := json.Marshal(info)
	_ = store.Set("user123", infoJSON, 0) // Ignoring error for brevity

	// Define a middleware instance with default configuration
	middleware := twofa.New(twofa.Config{
		Secret:       secret,
		Storage:      store,
		ContextKey:   "user123",
		RedirectURL:  "/2fa",
		CookieMaxAge: 86400,
		CookieName:   "twofa_cookie",
		TokenLookup:  "header:Authorization,query:token,form:token,param:token,cookie:token",
	})

	// Create a new Fiber app and register the middleware
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user123", "user123")
		return c.Next()
	})
	app.Use(middleware)

	// Define routes that will be used for testing
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	app.Post("/", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Generate a valid 2FA token
	totp := gotp.NewDefaultTOTP(secret)
	validToken := totp.Now()

	// Create a separate instance of the Middleware struct for testing
	testMiddleware := &twofa.Middleware{
		Config: &twofa.Config{
			Secret: secret,
		},
	}

	// Define test cases
	testCases := []struct {
		name             string
		requestURL       string
		requestMethod    string
		requestBody      io.Reader
		requestHeaders   map[string]string
		requestCookies   []*http.Cookie
		expectedStatus   int
		expectedLocation string
		expectedBody     string
		setupFunc        func()
	}{
		{
			name:             "GET request without token",
			requestURL:       "https://hack/",
			requestMethod:    "GET",
			requestBody:      nil,
			requestHeaders:   nil,
			requestCookies:   nil,
			expectedStatus:   fiber.StatusFound,
			expectedLocation: "/2fa",
		},
		{
			name:           "GET request with valid token in query parameter",
			requestURL:     fmt.Sprintf("https://hack/?token=%s", validToken),
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: nil,
			expectedStatus: fiber.StatusOK,
		},
		{
			name:          "GET request with valid token in header",
			requestURL:    "https://hack/",
			requestMethod: "GET",
			requestBody:   nil,
			requestHeaders: map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", validToken),
			},
			requestCookies: nil,
			expectedStatus: fiber.StatusOK,
		},
		{
			name:           "POST request with valid token in form data",
			requestURL:     "https://hack/",
			requestMethod:  "POST",
			requestBody:    strings.NewReader(fmt.Sprintf("token=%s", validToken)),
			requestHeaders: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			requestCookies: nil,
			expectedStatus: fiber.StatusOK,
		},
		{
			name:           "GET request with valid token in cookie",
			requestURL:     "https://hack/",
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: []*http.Cookie{{Name: "token", Value: validToken}},
			expectedStatus: fiber.StatusOK,
		},
		{
			name:           "GET request with valid cookie",
			requestURL:     "https://hack/",
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: []*http.Cookie{
				{
					Name:  "twofa_cookie",
					Value: testMiddleware.GenerateCookieValue(time.Now().Add(time.Hour)),
				},
			},
			expectedStatus: fiber.StatusOK,
		},
		{
			name:           "GET request with invalid cookie",
			requestURL:     "https://hack/",
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: []*http.Cookie{
				{
					Name:  "twofa_cookie",
					Value: "invalid_cookie_value",
				},
			},
			expectedStatus:   fiber.StatusFound,
			expectedLocation: "/2fa",
		},
		{
			name:           "Invalid 2FA token",
			requestURL:     "https://hack/?token=invalid_token",
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: nil,
			expectedStatus: fiber.StatusUnauthorized,
			expectedBody:   "Invalid 2FA token",
		},
		// Add more test cases as needed
	}

	// Run subtests in parallel
	for _, tc := range testCases {
		tc := tc // Capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create a new HTTP request
			req := httptest.NewRequest(tc.requestMethod, tc.requestURL, tc.requestBody)
			for key, value := range tc.requestHeaders {
				req.Header.Set(key, value)
			}
			for _, cookie := range tc.requestCookies {
				req.AddCookie(cookie)
			}

			// Perform the request
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("Failed to perform request: %v", err)
			}
			defer resp.Body.Close()

			// Check the response status code
			if resp.StatusCode != tc.expectedStatus {
				t.Logf("Request: %s %s", req.Method, req.URL)
				t.Logf("Response: %d", resp.StatusCode)
				t.Errorf("Expected status code %d, but got %d", tc.expectedStatus, resp.StatusCode)
			}

			// Check the response location header if expectedLocation is set
			if tc.expectedLocation != "" {
				location := resp.Header.Get("Location")
				if location != tc.expectedLocation {
					t.Errorf("Expected location header %q, but got %q", tc.expectedLocation, location)
				}
			}
		})
	}
}

func customLogger(t *testing.T) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Log the request
		t.Logf("Request: %s %s", c.Method(), c.OriginalURL())

		// Continue with the middleware chain
		err := c.Next()

		// After continuing with the middleware, log the response
		t.Logf("Response: %d", c.Response().StatusCode())

		return err
	}
}

func TestMiddleware_SkipNext(t *testing.T) {
	middleware := twofa.New(twofa.Config{
		Next: func(c *fiber.Ctx) bool {
			return true // Always skip the middleware
		},
	})

	app := fiber.New()
	app.Use(middleware)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Middleware skipped")
	})

	req := httptest.NewRequest("GET", "https://hack/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status code %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	if string(body) != "Middleware skipped" {
		t.Errorf("Expected body to be 'Middleware skipped', got '%s'", string(body))
	}
}

func TestMiddleware_SkipCookies(t *testing.T) {
	middleware := twofa.New(twofa.Config{
		SkipCookies: []string{"/skip"},
	})

	app := fiber.New()
	app.Use(middleware)
	app.Get("/skip", func(c *fiber.Ctx) error {
		return c.SendString("Path skipped")
	})

	req := httptest.NewRequest("GET", "https://hack/skip", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}

	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("Expected status code %d, got %d", fiber.StatusOK, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	if string(body) != "Path skipped" {
		t.Errorf("Expected body to be 'Path skipped', got '%s'", string(body))
	}
}

func TestMiddleware_Handle_StorageGetFail(t *testing.T) {
	secret := gotp.RandomSecret(16)
	// Use a custom storage that fails on Get operation
	store := &failingStorage{
		Storage: memory.New(),
	}

	middleware := twofa.New(twofa.Config{
		Storage:    store,
		ContextKey: "user123x",
		Secret:     secret,
	})

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user123x", "user123")
		return c.Next()
	})
	app.Use(middleware)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Should not get here")
	})

	req := httptest.NewRequest("GET", "https://hack/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Error when sending request to the app: %v", err)
	}

	if resp.StatusCode != fiber.StatusInternalServerError {
		t.Errorf("Expected status code %d, got %d", fiber.StatusInternalServerError, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %v", err)
	}
	if string(body) != "failed to retrieve 2FA information" {
		t.Errorf("Expected error message 'failed to retrieve 2FA information', got '%s'", string(body))
	}
}

// failingStorage is a custom storage that fails on Get operation
type failingStorage struct {
	*memory.Storage
}

func (s *failingStorage) Get(key string) ([]byte, error) {
	return nil, fmt.Errorf("storage get error")
}

func TestMiddleware_Handle_InfoNotFoundInStorage(t *testing.T) {
	store := memory.New()
	middleware := twofa.New(twofa.Config{
		Storage:     store,
		ContextKey:  "user123x",
		RedirectURL: "/2fa",
		CookieName:  "twofa_cookie",
	})

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user123x", "user123")
		return c.Next()
	})
	app.Use(middleware)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Should not get here")
	})

	req := httptest.NewRequest("GET", "https://hack/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Error when sending request to the app: %v", err)
	}

	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Errorf("Expected status code %d for missing 2FA info, but got %d", fiber.StatusUnauthorized, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %v", err)
	}
	if string(body) != "2FA information not found" {
		t.Errorf("Expected error message '2FA information not found', got '%s'", string(body))
	}
}

func TestMiddleware_GenerateQRcodePath(t *testing.T) {
	secret := gotp.RandomSecret(16)
	// Create a new Fiber app
	app := fiber.New()

	// Create an in-memory storage
	storage := memory.New()

	// Create a new Middleware instance with a custom ContextKey, Issuer, and JSONUnmarshal
	middleware := &twofa.Middleware{
		Config: &twofa.Config{
			ContextKey:    "accountName",
			Issuer:        "MyApp",
			Secret:        secret,
			Storage:       storage,
			JSONMarshal:   json.Marshal,   // Set the JSONMarshal field
			JSONUnmarshal: json.Unmarshal, // Set the JSONUnmarshal field
			Encode: twofa.EncodeConfig{
				Level: qrcode.Medium,
				Size:  256,
			},
			QRCode: twofa.QRCodeConfig{
				Content: "otpauth://totp/%s:%s?secret=%s&issuer=%s",
			},
		},
	}

	// Store the 2FA information in the storage for the test account
	info := &twofa.Info{
		Secret: secret,
	}
	rawInfo, _ := middleware.Config.JSONMarshal(info)
	storage.Set("gopher@example.com", rawInfo, 0)

	// Define a test handler that sets the account name in c.Locals and calls GenerateQRcodePath
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("accountName", "gopher@example.com")
		return middleware.GenerateQRcodePath(c)
	})

	// Send a test request to the "/test" route
	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Error when sending request to the app: %v", err)
	}

	// Check if the response status code is 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// Check if the response content type is "image/png"
	contentType := resp.Header.Get("Content-Type")
	if contentType != "image/png" {
		t.Errorf("Expected content type 'image/png', got '%s'", contentType)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %v", err)
	}

	// Decode the response body as a PNG image
	img, err := png.Decode(bytes.NewReader(body))
	if err != nil {
		t.Errorf("Error decoding response body as PNG: %v", err)
	}

	// Check if the decoded image has the expected dimensions
	expectedWidth := 256
	expectedHeight := 256
	if img.Bounds().Dx() != expectedWidth || img.Bounds().Dy() != expectedHeight {
		t.Errorf("Expected image dimensions %dx%d, got %dx%d", expectedWidth, expectedHeight, img.Bounds().Dx(), img.Bounds().Dy())
	}
}

func TestMiddleware_GenerateQRcodePath_CustomImage(t *testing.T) {
	secret := gotp.RandomSecret(16)
	// Create a new Fiber app
	app := fiber.New()

	// Create an in-memory storage
	storage := memory.New()

	// Create a custom QR code image
	customImage := image.NewRGBA(image.Rect(0, 0, 100, 100))
	// Fill the custom image with some color (e.g., red)
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			customImage.Set(i, j, color.RGBA{255, 0, 0, 255})
		}
	}

	// Create a new Middleware instance with a custom ContextKey, Issuer, JSONMarshal, JSONUnmarshal, and QRcodeImage
	middleware := &twofa.Middleware{
		Config: &twofa.Config{
			ContextKey:    "accountName",
			Issuer:        "MyApp",
			Secret:        secret,
			Storage:       storage,
			JSONMarshal:   json.Marshal,   // Set the JSONMarshal field
			JSONUnmarshal: json.Unmarshal, // Set the JSONUnmarshal field
			QRCode: twofa.QRCodeConfig{
				Image:   customImage, // Set the custom QR code image
				Content: "otpauth://totp/%s:%s?secret=%s&issuer=%s",
			},
		},
	}

	// Store the 2FA information in the storage for the test account
	// Note: This info manager is useful for writing tests during open-source development because Go has a rich ecosystem and tooling unlike other language mostly is poor.
	// It eliminates the need to spend money on renting a database solely for testing purposes.
	info := &twofa.Info{
		Secret: secret,
	}
	rawInfo, err := middleware.Config.JSONMarshal(info)
	if err != nil {
		t.Fatalf("Error marshaling 2FA information: %v", err)
	}
	storage.Set("gopher@example.com", rawInfo, 0)

	// Define a test handler that sets the account name in c.Locals and calls GenerateQRcodePath
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("accountName", "gopher@example.com")
		return middleware.GenerateQRcodePath(c)
	})

	// Send a test request to the "/test" route
	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Error when sending request to the app: %v", err)
	}

	// Check if the response status code is 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// Check if the response content type is "image/png"
	contentType := resp.Header.Get("Content-Type")
	if contentType != "image/png" {
		t.Errorf("Expected content type 'image/png', got '%s'", contentType)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %v", err)
	}

	// Decode the response body as a PNG image
	img, err := png.Decode(bytes.NewReader(body))
	if err != nil {
		t.Errorf("Error decoding response body as PNG: %v", err)
	}

	// Check if the decoded image matches the custom QR code image
	if !reflect.DeepEqual(img, customImage) {
		t.Error("Decoded image does not match the custom QR code image")
	}
}

func TestMiddleware_SendInternalErrorResponse(t *testing.T) {
	testCases := []struct {
		name         string
		responseMIME string
		expectedBody string
	}{
		{
			name:         "Plain text response",
			responseMIME: fiber.MIMETextPlainCharsetUTF8,
			expectedBody: "ContextKey is not set",
		},
		{
			name:         "JSON response",
			responseMIME: fiber.MIMEApplicationJSON,
			expectedBody: "{\"error\":\"ContextKey is not set\"}",
		},
		{
			name:         "XML response",
			responseMIME: fiber.MIMEApplicationXML,
			expectedBody: "<error><message>ContextKey is not set</message></error>",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := twofa.Config{
				ResponseMIME: tc.responseMIME,
			}
			middleware := twofa.New(config)

			app := fiber.New()
			app.Use(middleware)
			app.Get("/", func(c *fiber.Ctx) error {
				return c.Status(fiber.StatusInternalServerError).SendString("ContextKey is not set")
			})

			req := httptest.NewRequest("GET", "/", nil)
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("Error when sending request to the app: %v", err)
			}

			if resp.StatusCode != fiber.StatusInternalServerError {
				t.Errorf("Expected status code %d, got %d", fiber.StatusInternalServerError, resp.StatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Error reading response body: %v", err)
			}

			if strings.TrimSpace(string(body)) != tc.expectedBody {
				t.Errorf("Expected response body '%s', got '%s'", tc.expectedBody, string(body))
			}
		})
	}
}

func TestMiddleware_SendUnauthorizedResponse(t *testing.T) {
	testCases := []struct {
		name         string
		responseMIME string
		expectedBody string
	}{
		{
			name:         "Plain text response",
			responseMIME: fiber.MIMETextPlainCharsetUTF8,
			expectedBody: "2FA information not found",
		},
		{
			name:         "JSON response",
			responseMIME: fiber.MIMEApplicationJSON,
			expectedBody: "{\"error\":\"2FA information not found\"}",
		},
		{
			name:         "XML response",
			responseMIME: fiber.MIMEApplicationXML,
			expectedBody: "<error><message>2FA information not found</message></error>",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			store := memory.New()
			secret := gotp.RandomSecret(16)
			config := twofa.Config{
				ResponseMIME: tc.responseMIME,
				Secret:       secret,
				ContextKey:   "gopher_testing",
				Storage:      store,
			}
			middleware := twofa.New(config)

			app := fiber.New()
			app.Use(func(c *fiber.Ctx) error {
				c.Locals(config.ContextKey, "test_context_key")
				return c.Next()
			})
			app.Use(middleware)
			app.Get("/", func(c *fiber.Ctx) error {
				return c.SendString("OK")
			})

			req := httptest.NewRequest("GET", "/", nil)
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("Error when sending request to the app: %v", err)
			}

			if resp.StatusCode != fiber.StatusUnauthorized {
				t.Errorf("Expected status code %d, got %d", fiber.StatusUnauthorized, resp.StatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Error reading response body: %v", err)
			}

			if strings.TrimSpace(string(body)) != tc.expectedBody {
				t.Errorf("Expected response body '%s', got '%s'", tc.expectedBody, string(body))
			}
		})
	}
}

func TestMiddleware_CustomUnauthorizedHandler(t *testing.T) {
	store := memory.New()
	secret := gotp.RandomSecret(16)
	config := twofa.Config{
		Secret:     secret,
		ContextKey: "gopher_testing",
		Storage:    store,
		UnauthorizedHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusUnauthorized).SendString("Custom unauthorized handler")
		},
	}
	middleware := twofa.New(config)

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(config.ContextKey, "test_context_key")
		return c.Next()
	})
	app.Use(middleware)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest("GET", "/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Error when sending request to the app: %v", err)
	}

	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Errorf("Expected status code %d, got %d", fiber.StatusUnauthorized, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %v", err)
	}

	expectedBody := "Custom unauthorized handler"
	if string(body) != expectedBody {
		t.Errorf("Expected response body '%s', got '%s'", expectedBody, string(body))
	}
}

func TestMiddleware_CustomInternalErrorHandler(t *testing.T) {
	store := memory.New()
	secret := gotp.RandomSecret(16)
	config := twofa.Config{
		Secret:     secret,
		ContextKey: "gopher_testing",
		Storage:    store,
		InternalErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusInternalServerError).SendString("Custom internal error handler")
		},
	}
	middleware := twofa.New(config)

	app := fiber.New()
	app.Use(middleware)
	app.Get("/", func(c *fiber.Ctx) error {
		return fiber.NewError(fiber.StatusInternalServerError, "Internal server error")
	})

	req := httptest.NewRequest("GET", "/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Error when sending request to the app: %v", err)
	}

	if resp.StatusCode != fiber.StatusInternalServerError {
		t.Errorf("Expected status code %d, got %d", fiber.StatusInternalServerError, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %v", err)
	}

	expectedBody := "Custom internal error handler"
	if string(body) != expectedBody {
		t.Errorf("Expected response body '%s', got '%s'", expectedBody, string(body))
	}
}

func TestMiddleware_GetContextKey(t *testing.T) {
	testCases := []struct {
		name          string
		contextKey    string
		contextValue  any
		expectedKey   string
		expectedError string
	}{
		{
			name:          "Valid context key",
			contextKey:    "user_id",
			contextValue:  "123",
			expectedKey:   "123",
			expectedError: "",
		},
		{
			name:          "Empty context key",
			contextKey:    "",
			contextValue:  nil,
			expectedKey:   "",
			expectedError: "ContextKey is not set",
		},
		{
			name:          "Context key not set",
			contextKey:    "user_id",
			contextValue:  nil,
			expectedKey:   "",
			expectedError: "ContextKey is not set",
		},
		{
			name:          "Invalid context value type",
			contextKey:    "user_id",
			contextValue:  123,
			expectedKey:   "",
			expectedError: "failed to retrieve context key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := twofa.Config{
				ContextKey: tc.contextKey,
			}
			middleware := twofa.New(config)

			app := fiber.New()
			app.Use(func(c *fiber.Ctx) error {
				if tc.contextValue != nil {
					c.Locals(tc.contextKey, tc.contextValue)
				}
				return c.Next()
			})
			app.Use(middleware)
			app.Get("/", func(c *fiber.Ctx) error {
				return c.SendString("OK")
			})

			req := httptest.NewRequest("GET", "/", nil)
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("Error when sending request to the app: %v", err)
			}

			if resp.StatusCode != fiber.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				if tc.expectedError != "" && !strings.Contains(string(body), tc.expectedError) {
					t.Errorf("Expected error '%s', got '%s'", tc.expectedError, string(body))
				}
			} else {
				if tc.expectedError != "" {
					t.Errorf("Expected error '%s', but got no error", tc.expectedError)
				}
			}
		})
	}
}

func TestMiddleware_GenerateQRcodePath_Error(t *testing.T) {
	secret := gotp.RandomSecret(16)
	// Create a new Fiber app
	app := fiber.New()

	// Create an in-memory storage
	storage := memory.New()

	// Create a new Middleware instance with a custom ContextKey, Issuer, and JSONUnmarshal
	middleware := &twofa.Middleware{
		Config: &twofa.Config{
			ContextKey:    "accountName",
			Issuer:        "MyApp",
			Secret:        secret,
			Storage:       storage,
			JSONMarshal:   json.Marshal,   // Set the JSONMarshal field
			JSONUnmarshal: json.Unmarshal, // Set the JSONUnmarshal field
			Encode: twofa.EncodeConfig{
				Level: qrcode.Medium,
				Size:  256,
			},
			QRCode: twofa.QRCodeConfig{
				Content: "otpauth://totp/%s:%s?secret=%s&issuer=%s",
			},
		},
	}

	// Define a test handler that sets an invalid account name in c.Locals and calls GenerateQRcodePath
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("accountName", "invalid@example.com")
		return middleware.GenerateQRcodePath(c)
	})

	// Send a test request to the "/test" route
	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Error when sending request to the app: %v", err)
	}

	// Check if the response status code is 401 Unauthorized
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status code %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %v", err)
	}

	// Check if the response body contains the expected error message
	expectedErrorMessage := "2FA information not found"
	if !strings.Contains(string(body), expectedErrorMessage) {
		t.Errorf("Expected error message '%s', got '%s'", expectedErrorMessage, string(body))
	}
}

func TestMiddlewareUUIDContextKey_Handle(t *testing.T) {
	// Set up the storage with an in-memory store for simplicity
	store := memory.New()
	secret := gotp.RandomSecret(16)

	// Generate a UUID for the context key
	contextKey := uuid.New().String()

	// Create a default Info struct and store it for Simulate State
	info := twofa.Info{
		ContextKey:     contextKey,
		Secret:         secret,
		CookieValue:    "",
		ExpirationTime: time.Time{},
	}
	infoJSON, _ := json.Marshal(info)
	_ = store.Set("gopher@example.com", infoJSON, 0) // Ignoring error for brevity

	// Define a middleware instance with default configuration
	middleware := twofa.New(twofa.Config{
		Secret:       secret,
		Storage:      store,
		ContextKey:   contextKey,
		RedirectURL:  "/2fa",
		CookieMaxAge: 86400,
		CookieName:   "twofa_cookie",
		TokenLookup:  "header:Authorization,query:token,form:token,param:token,cookie:token",
	})

	// Create a new Fiber app and register the middleware
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(contextKey, "gopher@example.com")
		return c.Next()
	})
	app.Use(middleware)

	// Define routes that will be used for testing
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	app.Post("/", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Generate a valid 2FA token
	totp := gotp.NewDefaultTOTP(secret)
	validToken := totp.Now()

	// Create a separate instance of the Middleware struct for testing
	testMiddleware := &twofa.Middleware{
		Config: &twofa.Config{
			Secret: secret,
		},
	}

	// Generate cryptographically secure random data
	randomData := make([]byte, 16)
	_, err := rand.Read(randomData)
	if err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	// Create a UUID using the random data
	randomUUID, err := uuid.FromBytes(randomData)
	if err != nil {
		t.Fatalf("Failed to create UUID from random data: %v", err)
	}

	// Create a separate instance of the Middleware struct for testing
	testMiddlewareRandomUUID := &twofa.Middleware{
		Config: &twofa.Config{
			Secret:     secret,
			ContextKey: randomUUID.String(),
		},
	}

	// Define test cases
	testCases := []struct {
		name             string
		requestURL       string
		requestMethod    string
		requestBody      io.Reader
		requestHeaders   map[string]string
		requestCookies   []*http.Cookie
		expectedStatus   int
		expectedLocation string
		expectedBody     string
		setupFunc        func()
	}{
		{
			name:             "GET request without token",
			requestURL:       "https://hack/",
			requestMethod:    "GET",
			requestBody:      nil,
			requestHeaders:   nil,
			requestCookies:   nil,
			expectedStatus:   fiber.StatusFound,
			expectedLocation: "/2fa",
		},
		{
			name:           "GET request with valid token in query parameter",
			requestURL:     fmt.Sprintf("https://hack/?token=%s", validToken),
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: nil,
			expectedStatus: fiber.StatusOK,
		},
		{
			name:          "GET request with valid token in header",
			requestURL:    "https://hack/",
			requestMethod: "GET",
			requestBody:   nil,
			requestHeaders: map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", validToken),
			},
			requestCookies: nil,
			expectedStatus: fiber.StatusOK,
		},
		{
			name:           "POST request with valid token in form data",
			requestURL:     "https://hack/",
			requestMethod:  "POST",
			requestBody:    strings.NewReader(fmt.Sprintf("token=%s", validToken)),
			requestHeaders: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			requestCookies: nil,
			expectedStatus: fiber.StatusOK,
		},
		{
			name:           "GET request with valid token in cookie",
			requestURL:     "https://hack/",
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: []*http.Cookie{{Name: "token", Value: validToken}},
			expectedStatus: fiber.StatusOK,
		},
		{
			name:           "GET request with valid cookie",
			requestURL:     "https://hack/",
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: []*http.Cookie{
				{
					Name:  "twofa_cookie",
					Value: testMiddleware.GenerateCookieValue(time.Now().Add(time.Hour)),
				},
			},
			expectedStatus: fiber.StatusOK,
		},
		{
			name:           "GET request with invalid cookie",
			requestURL:     "https://hack/",
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: []*http.Cookie{
				{
					Name:  "twofa_cookie",
					Value: "invalid_cookie_value",
				},
			},
			expectedStatus:   fiber.StatusFound,
			expectedLocation: "/2fa",
		},
		{
			name:           "Invalid 2FA token",
			requestURL:     "https://hack/?token=invalid_token",
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: nil,
			expectedStatus: fiber.StatusUnauthorized,
			expectedBody:   "Invalid 2FA token",
		},

		{
			name:           "GET request with Random UUID value",
			requestURL:     fmt.Sprintf("https://rand.uuid.hack/?token=%s", validToken),
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: nil,
			expectedStatus: fiber.StatusOK,
			setupFunc: func() {
				// Update the middleware configuration with the UUID value
				testMiddlewareRandomUUID.Config.ContextKey = randomUUID.String()
			},
		},
		{
			name:          "GET request with valid token in header and Random UUID value",
			requestURL:    "https://rand.uuid.hack/",
			requestMethod: "GET",
			requestBody:   nil,
			requestHeaders: map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", validToken),
			},
			requestCookies: nil,
			expectedStatus: fiber.StatusOK,
			setupFunc: func() {
				// Update the middleware configuration with the UUID value
				testMiddlewareRandomUUID.Config.ContextKey = randomUUID.String()
			},
		},
		{
			name:           "POST request with valid token in form data and Random UUID value",
			requestURL:     "https://rand.uuid.hack/",
			requestMethod:  "POST",
			requestBody:    strings.NewReader(fmt.Sprintf("token=%s", validToken)),
			requestHeaders: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			requestCookies: nil,
			expectedStatus: fiber.StatusOK,
			setupFunc: func() {
				// Update the middleware configuration with the UUID value
				testMiddlewareRandomUUID.Config.ContextKey = randomUUID.String()
			},
		},
		{
			name:           "GET request with valid token in cookie and Random UUID value",
			requestURL:     "https://rand.uuid.hack/",
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: []*http.Cookie{{Name: "token", Value: validToken}},
			expectedStatus: fiber.StatusOK,
			setupFunc: func() {
				// Update the middleware configuration with the UUID value
				testMiddlewareRandomUUID.Config.ContextKey = randomUUID.String()
			},
		},
		{
			name:           "GET request with valid cookie and Random UUID value",
			requestURL:     "https://rand.uuid.hack/",
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: []*http.Cookie{
				{
					Name:  "twofa_cookie",
					Value: testMiddleware.GenerateCookieValue(time.Now().Add(time.Hour)),
				},
			},
			expectedStatus: fiber.StatusOK,
			setupFunc: func() {
				// Update the middleware configuration with the UUID value
				testMiddlewareRandomUUID.Config.ContextKey = randomUUID.String()
			},
		},
		{
			name:           "GET request with invalid cookie and Random UUID value",
			requestURL:     "https://rand.uuid.hack/",
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: []*http.Cookie{
				{
					Name:  "twofa_cookie",
					Value: "invalid_cookie_value",
				},
			},
			expectedStatus:   fiber.StatusFound,
			expectedLocation: "/2fa",
			setupFunc: func() {
				// Update the middleware configuration with the UUID value
				testMiddlewareRandomUUID.Config.ContextKey = randomUUID.String()
			},
		},
		{
			name:           "Invalid 2FA token with Random UUID value",
			requestURL:     "https://rand.uuid.hack/?token=invalid_token",
			requestMethod:  "GET",
			requestBody:    nil,
			requestHeaders: nil,
			requestCookies: nil,
			expectedStatus: fiber.StatusUnauthorized,
			expectedBody:   "Invalid 2FA token",
			setupFunc: func() {
				// Update the middleware configuration with the UUID value
				testMiddlewareRandomUUID.Config.ContextKey = randomUUID.String()
			},
		},

		// Add more test cases as needed
	}

	// Run subtests in parallel
	for _, tc := range testCases {
		tc := tc // Capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Run the setup function if provided
			if tc.setupFunc != nil {
				tc.setupFunc()
			}

			// Create a new HTTP request
			req := httptest.NewRequest(tc.requestMethod, tc.requestURL, tc.requestBody)
			for key, value := range tc.requestHeaders {
				req.Header.Set(key, value)
			}
			for _, cookie := range tc.requestCookies {
				req.AddCookie(cookie)
			}

			// Perform the request
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("Failed to perform request: %v", err)
			}
			defer resp.Body.Close()

			// Check the response status code
			if resp.StatusCode != tc.expectedStatus {
				t.Logf("Request: %s %s", req.Method, req.URL)
				t.Logf("Response: %d", resp.StatusCode)
				t.Errorf("Expected status code %d, but got %d", tc.expectedStatus, resp.StatusCode)
			}

			// Check the response location header if expectedLocation is set
			if tc.expectedLocation != "" {
				location := resp.Header.Get("Location")
				if location != tc.expectedLocation {
					t.Errorf("Expected location header %q, but got %q", tc.expectedLocation, location)
				}
			}
		})
	}
}
