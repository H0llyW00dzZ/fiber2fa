// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package twofa_test

import (
	"bytes"
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
		Secret:        secret,
		Storage:       store,
		ContextKey:    "user123",
		RedirectURL:   "/2fa",
		CookieMaxAge:  86400,
		CookieName:    "twofa_cookie",
		TokenLookup:   "header:Authorization,query:token,form:token,param:token,cookie:token",
		JSONMarshal:   json.Marshal,
		JSONUnmarshal: json.Unmarshal,
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
	store := memory.New()
	middleware := twofa.New(twofa.Config{
		Storage: store,
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
	store := memory.New()
	middleware := twofa.New(twofa.Config{
		Storage:     store,
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
	// Use a custom storage that fails on Get operation
	store := &failingStorage{}

	middleware := twofa.New(twofa.Config{
		Storage:    store,
		ContextKey: "user123x",
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
	memory.Storage
}

func (s *failingStorage) Get(key string) ([]byte, error) {
	return nil, fmt.Errorf("storage get error")
}

func TestMiddleware_Handle_NoContextKey(t *testing.T) {
	// Set up the storage with an in-memory store for simplicity
	store := memory.New()

	// Create a default Info struct and store it for simulate state
	info := twofa.Info{
		ContextKey:     "user123",
		Secret:         "secret",
		CookieValue:    "",
		ExpirationTime: time.Time{},
	}
	infoJSON, _ := json.Marshal(info)
	_ = store.Set("user123", infoJSON, 0) // Ignoring error for brevity

	// Create a new Middleware instance with the in-memory storage and without setting the ContextKey
	middleware := twofa.New(twofa.Config{
		Storage:       store,
		ContextKey:    "", // Not setting the ContextKey
		RedirectURL:   "/2fa",
		CookieMaxAge:  86400,
		CookieName:    "twofa_cookie",
		TokenLookup:   "header:Authorization",
		JSONMarshal:   json.Marshal,
		JSONUnmarshal: json.Unmarshal,
	})

	// Create a new Fiber app and use the middleware
	app := fiber.New()

	// Use a custom middleware to simulate setting a context key, but do not actually set it
	app.Use(func(c *fiber.Ctx) error {
		// Intentionally do not set the context key
		return c.Next()
	})

	// Then use the actual middleware
	app.Use(middleware)

	// Define a simple handler that will be called after the middleware
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Should not get here")
	})

	// Simulate a request to the "/" route using the Fiber app's Test method
	req := httptest.NewRequest("GET", "https://hack/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Error when sending request to the app: %v", err)
	}

	// Verify that the status code is as expected for missing context key
	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Errorf("Expected status code %d for missing context key, but got %d", fiber.StatusUnauthorized, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %v", err)
	}
	if string(body) != "ContextKey is not set" {
		t.Errorf("Expected error message 'ContextKey is not set', got '%s'", string(body))
	}
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

func TestMiddleware_GenerateBarcodePath(t *testing.T) {
	secret := gotp.RandomSecret(16)
	// Create a new Fiber app
	app := fiber.New()

	// Create an in-memory storage
	storage := memory.New()

	// Create a new Middleware instance with a custom ContextKey, Issuer, and JSONUnmarshal
	middleware := &twofa.Middleware{
		Config: &twofa.Config{
			ContextKey:    "accountName",
			AccountName:   "gopherAccount",
			Issuer:        "MyApp",
			Secret:        secret,
			Storage:       storage,
			JSONMarshal:   json.Marshal,   // Set the JSONMarshal field
			JSONUnmarshal: json.Unmarshal, // Set the JSONUnmarshal field
		},
	}

	// Store the 2FA information in the storage for the test account
	info := &twofa.Info{
		Secret: secret,
	}
	rawInfo, _ := middleware.Config.JSONMarshal(info)
	storage.Set("gopher@example.com", rawInfo, 0)

	// Define a test handler that sets the account name in c.Locals and calls GenerateBarcodePath
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("accountName", "gopher@example.com")
		return middleware.GenerateBarcodePath(c)
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

func TestMiddleware_GenerateBarcodePath_CustomImage(t *testing.T) {
	secret := gotp.RandomSecret(16)
	// Create a new Fiber app
	app := fiber.New()

	// Create an in-memory storage
	storage := memory.New()

	// Create a custom barcode image
	customImage := image.NewRGBA(image.Rect(0, 0, 100, 100))
	// Fill the custom image with some color (e.g., red)
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			customImage.Set(i, j, color.RGBA{255, 0, 0, 255})
		}
	}

	// Create a new Middleware instance with a custom ContextKey, Issuer, JSONMarshal, JSONUnmarshal, and BarcodeImage/QRCode
	middleware := &twofa.Middleware{
		Config: &twofa.Config{
			ContextKey:    "accountName",
			Issuer:        "MyApp",
			Secret:        secret,
			Storage:       storage,
			JSONMarshal:   json.Marshal,   // Set the JSONMarshal field
			JSONUnmarshal: json.Unmarshal, // Set the JSONUnmarshal field
			BarcodeImage:  customImage,    // Set the custom barcode/qrcode image
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

	// Define a test handler that sets the account name in c.Locals and calls GenerateBarcodePath
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("accountName", "gopher@example.com")
		return middleware.GenerateBarcodePath(c)
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

	// Check if the decoded image matches the custom barcode image
	if !reflect.DeepEqual(img, customImage) {
		t.Error("Decoded image does not match the custom barcode image")
	}
}
