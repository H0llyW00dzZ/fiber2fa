// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package twofa_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	twofa "github.com/H0llyW00dzZ/fiber2fa"
	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/storage/memory/v2"
	"github.com/xlzd/gotp"
)

func BenchmarSonicJSONkMiddleware_Handle(b *testing.B) {
	// Set up the storage with an in-memory store for simplicity
	store := memory.New()
	secret := gotp.RandomSecret(16)

	// Create a default Info struct and store it for Simulate State
	info := twofa.Info{
		ContextKey:     "gopherBenchmarkOTP1",
		Secret:         secret,
		CookieValue:    "",
		ExpirationTime: time.Time{},
	}
	infoJSON, _ := sonic.Marshal(info)
	_ = store.Set("gopherBenchmarkOTP1", infoJSON, 0) // Ignoring error for brevity

	// Define a middleware instance with default configuration
	middleware := twofa.New(twofa.Config{
		Secret:        secret,
		Storage:       store,
		ContextKey:    "gopherBenchmarkOTP1",
		RedirectURL:   "/2fa",
		CookieMaxAge:  86400,
		CookieName:    "twofa_cookie",
		TokenLookup:   "header:Authorization",
		JSONMarshal:   sonic.Marshal,
		JSONUnmarshal: sonic.Unmarshal,
	})

	// Create a new Fiber app and register the middleware
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("gopherBenchmarkOTP1", "gopherBenchmarkOTP1")
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

	// Define the token lookup scenarios
	scenarios := []struct {
		name           string
		requestURL     string
		requestMethod  string
		requestBody    io.Reader
		requestHeaders map[string]string
		requestCookies []*http.Cookie
		expectedStatus int
	}{
		{
			name:          "Header",
			requestURL:    "https://hack/",
			requestMethod: "GET",
			requestHeaders: map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", totp.Now()),
			},
			expectedStatus: fiber.StatusOK,
		},
	}

	// Run the benchmark scenarios in parallel
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for _, scenario := range scenarios {
				// Create a new HTTP request for each scenario
				req := httptest.NewRequest(scenario.requestMethod, scenario.requestURL, scenario.requestBody)
				for key, value := range scenario.requestHeaders {
					req.Header.Set(key, value)
				}
				for _, cookie := range scenario.requestCookies {
					req.AddCookie(cookie)
				}

				// Perform the request
				resp, err := app.Test(req)
				if err != nil {
					b.Fatalf("Failed to perform request: %v", err)
				}
				resp.Body.Close()
			}
		}
	})
}

func BenchmarStdJSONkMiddleware_Handle(b *testing.B) {
	// Set up the storage with an in-memory store for simplicity
	store := memory.New()
	secret := gotp.RandomSecret(16)

	// Create a default Info struct and store it for Simulate State
	info := twofa.Info{
		ContextKey:     "gopherBenchmarkOTP2",
		Secret:         secret,
		CookieValue:    "",
		ExpirationTime: time.Time{},
	}
	infoJSON, _ := sonic.Marshal(info)
	_ = store.Set("gopherBenchmarkOTP2", infoJSON, 0) // Ignoring error for brevity

	// Define a middleware instance with default configuration
	middleware := twofa.New(twofa.Config{
		Secret:       secret,
		Storage:      store,
		ContextKey:   "gopherBenchmarkOTP2",
		RedirectURL:  "/2fa",
		CookieMaxAge: 86400,
		CookieName:   "twofa_cookie",
		TokenLookup:  "header:Authorization",
	})

	// Create a new Fiber app and register the middleware
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("gopherBenchmarkOTP2", "gopherBenchmarkOTP2")
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

	// Define the token lookup scenarios
	scenarios := []struct {
		name           string
		requestURL     string
		requestMethod  string
		requestBody    io.Reader
		requestHeaders map[string]string
		requestCookies []*http.Cookie
		expectedStatus int
	}{
		{
			name:          "Header",
			requestURL:    "https://hack/",
			requestMethod: "GET",
			requestHeaders: map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", totp.Now()),
			},
			expectedStatus: fiber.StatusOK,
		},
	}

	// Run the benchmark scenarios in parallel
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for _, scenario := range scenarios {
				// Create a new HTTP request for each scenario
				req := httptest.NewRequest(scenario.requestMethod, scenario.requestURL, scenario.requestBody)
				for key, value := range scenario.requestHeaders {
					req.Header.Set(key, value)
				}
				for _, cookie := range scenario.requestCookies {
					req.AddCookie(cookie)
				}

				// Perform the request
				resp, err := app.Test(req)
				if err != nil {
					b.Fatalf("Failed to perform request: %v", err)
				}
				resp.Body.Close()
			}
		}
	})
}
