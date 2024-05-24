// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package twofa_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	twofa "github.com/H0llyW00dzZ/fiber2fa"
	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/gofiber/storage/memory/v2"
	"github.com/xlzd/gotp"
)

func BenchmarkJSONSonicMiddlewareWithInvalidCookie(b *testing.B) {
	// Set up the storage with an in-memory store for simplicity
	store := memory.New()
	secret := gotp.RandomSecret(16)
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		c.Locals("sonic_benchmark", "sonic_benchmark1234")
		return c.Next()
	})

	app.Use(twofa.New(twofa.Config{
		Secret:        secret,
		Issuer:        "gopher",
		ContextKey:    "sonic_benchmark",
		CookieMaxAge:  86400,
		Storage:       store,
		JSONMarshal:   sonic.Marshal,
		JSONUnmarshal: sonic.Unmarshal,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set(fiber.HeaderCookie, "twofa_cookie=invalid-cookie-value")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp, _ := app.Test(req)
		utils.AssertEqual(b, fiber.StatusUnauthorized, resp.StatusCode)
	}
}

func BenchmarkJSONSonicWithValid2FA(b *testing.B) {
	// Set up the storage with an in-memory store for simplicity
	store := memory.New()
	secret := gotp.RandomSecret(16)
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		c.Locals("sonic_benchmark", "sonic_benchmark1234")
		return c.Next()
	})

	twoFAConfig := twofa.Config{
		Secret:        secret,
		Issuer:        "gopher",
		ContextKey:    "sonic_benchmark",
		CookieMaxAge:  86400,
		Storage:       store,
		JSONMarshal:   sonic.Marshal,
		JSONUnmarshal: sonic.Unmarshal,
		TokenLookup:   "query:token",
	}

	twoFAMiddleware := &twofa.Middleware{Config: &twoFAConfig}

	app.Use(twoFAMiddleware.Handle)

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	// Generate a valid 2FA token
	totp := gotp.NewDefaultTOTP(secret)
	token := totp.Now()

	// Create a valid 2FA cookie
	cookieValue := twoFAMiddleware.GenerateCookieValue(time.Now().Add(time.Duration(86400) * time.Second))

	// Store the 2FA information in the storage
	info := &twofa.Info{
		ContextKey:     "sonic_benchmark1234",
		Secret:         secret,
		CookieValue:    cookieValue,
		ExpirationTime: time.Time{},
	}
	infoJSON, _ := twoFAConfig.JSONMarshal(info)
	err := store.Set("sonic_benchmark1234", infoJSON, 0)
	if err != nil {
		b.Fatalf("Failed to store 2FA information: %v", err)
	}

	req := httptest.NewRequest(fiber.MethodGet, "/?token="+token, nil)
	req.Header.Set(fiber.HeaderCookie, "twofa_cookie="+cookieValue)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp, _ := app.Test(req)
		utils.AssertEqual(b, fiber.StatusOK, resp.StatusCode)
	}
}

func BenchmarkJSONSonicWithValidCookie(b *testing.B) {
	// Set up the storage with an in-memory store for simplicity
	store := memory.New()
	secret := gotp.RandomSecret(16)
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		c.Locals("sonic_benchmark", "sonic_benchmark1234")
		return c.Next()
	})

	twoFAConfig := twofa.Config{
		Secret:        secret,
		Issuer:        "gopher",
		ContextKey:    "sonic_benchmark",
		CookieMaxAge:  86400,
		Storage:       store,
		JSONMarshal:   sonic.Marshal,
		JSONUnmarshal: sonic.Unmarshal,
		TokenLookup:   "query:token",
	}

	twoFAMiddleware := &twofa.Middleware{Config: &twoFAConfig}

	app.Use(twoFAMiddleware.Handle)

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	// Generate a valid 2FA token
	totp := gotp.NewDefaultTOTP(secret)
	token := totp.Now()

	// Create a valid 2FA cookie
	cookieValue := twoFAMiddleware.GenerateCookieValue(time.Now().Add(time.Duration(86400) * time.Second))

	// Store the 2FA information in the storage
	info := &twofa.Info{
		ContextKey:     "sonic_benchmark1234",
		Secret:         secret,
		CookieValue:    cookieValue,
		ExpirationTime: time.Time{},
	}
	infoJSON, _ := twoFAConfig.JSONMarshal(info)
	err := store.Set("sonic_benchmark1234", infoJSON, 0)
	if err != nil {
		b.Fatalf("Failed to store 2FA information: %v", err)
	}

	// Create a request with the valid cookie
	req := httptest.NewRequest(fiber.MethodGet, "/?token="+token, nil)
	req.Header.Set(fiber.HeaderCookie, twoFAConfig.CookieName+"="+cookieValue)

	// Perform the initial request to generate and store the 2FA information
	resp, err := app.Test(req)
	if err != nil {
		b.Fatalf("Failed to perform initial request: %v", err)
	}
	defer resp.Body.Close()

	// Extract the generated cookie from the response
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == twoFAConfig.CookieName {
			cookieValue = cookie.Value
			break
		}
	}

	if cookieValue == "" {
		b.Fatalf("Failed to retrieve the generated cookie")
	}

	// Create a new request with the valid cookie
	req = httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set(fiber.HeaderCookie, twoFAConfig.CookieName+"="+cookieValue)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp, _ := app.Test(req)
		utils.AssertEqual(b, fiber.StatusOK, resp.StatusCode)
	}
}

func BenchmarkJSONStdLibraryMiddlewareWithInvalidCookie(b *testing.B) {
	// Set up the storage with an in-memory store for simplicity
	store := memory.New()
	secret := gotp.RandomSecret(16)
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		c.Locals("stdlibrary_benchmark", "stdlibrary_benchmark1234")
		return c.Next()
	})

	app.Use(twofa.New(twofa.Config{
		Secret:        secret,
		Issuer:        "gopher",
		ContextKey:    "stdlibrary_benchmark",
		CookieMaxAge:  86400,
		Storage:       store,
		JSONMarshal:   json.Marshal,
		JSONUnmarshal: json.Unmarshal,
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set(fiber.HeaderCookie, "twofa_cookie=invalid-cookie-value")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp, _ := app.Test(req)
		utils.AssertEqual(b, fiber.StatusUnauthorized, resp.StatusCode)
	}
}

func BenchmarkJSONStdLibraryMiddlewareWithValid2FA(b *testing.B) {
	// Set up the storage with an in-memory store for simplicity
	store := memory.New()
	secret := gotp.RandomSecret(16)
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		c.Locals("stdlibrary_benchmark", "stdlibrary_benchmark1234")
		return c.Next()
	})

	twoFAConfig := twofa.Config{
		Secret:        secret,
		Issuer:        "gopher",
		ContextKey:    "stdlibrary_benchmark",
		CookieMaxAge:  86400,
		Storage:       store,
		JSONMarshal:   json.Marshal,
		JSONUnmarshal: json.Unmarshal,
		TokenLookup:   "query:token",
	}

	twoFAMiddleware := &twofa.Middleware{Config: &twoFAConfig}

	app.Use(twoFAMiddleware.Handle)

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	// Generate a valid 2FA token
	totp := gotp.NewDefaultTOTP(secret)
	token := totp.Now()

	// Create a valid 2FA cookie
	cookieValue := twoFAMiddleware.GenerateCookieValue(time.Now().Add(time.Duration(86400) * time.Second))

	// Store the 2FA information in the storage
	info := &twofa.Info{
		ContextKey:     "stdlibrary_benchmark1234",
		Secret:         secret,
		CookieValue:    cookieValue,
		ExpirationTime: time.Time{},
	}
	infoJSON, _ := twoFAConfig.JSONMarshal(info)
	err := store.Set("stdlibrary_benchmark1234", infoJSON, 0)
	if err != nil {
		b.Fatalf("Failed to store 2FA information: %v", err)
	}

	req := httptest.NewRequest(fiber.MethodGet, "/?token="+token, nil)
	req.Header.Set(fiber.HeaderCookie, "twofa_cookie="+cookieValue)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp, _ := app.Test(req)
		utils.AssertEqual(b, fiber.StatusOK, resp.StatusCode)
	}
}

func BenchmarkJSONStdLibraryWithValidCookie(b *testing.B) {
	// Set up the storage with an in-memory store for simplicity
	store := memory.New()
	secret := gotp.RandomSecret(16)
	app := fiber.New()

	app.Use(func(c *fiber.Ctx) error {
		c.Locals("stdlibrary_benchmark", "stdlibrary_benchmark1234")
		return c.Next()
	})

	twoFAConfig := twofa.Config{
		Secret:        secret,
		Issuer:        "gopher",
		ContextKey:    "stdlibrary_benchmark",
		CookieMaxAge:  86400,
		Storage:       store,
		JSONMarshal:   json.Marshal,
		JSONUnmarshal: json.Unmarshal,
		TokenLookup:   "query:token",
	}

	twoFAMiddleware := &twofa.Middleware{Config: &twoFAConfig}

	app.Use(twoFAMiddleware.Handle)

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	// Generate a valid 2FA token
	totp := gotp.NewDefaultTOTP(secret)
	token := totp.Now()

	// Create a valid 2FA cookie
	cookieValue := twoFAMiddleware.GenerateCookieValue(time.Now().Add(time.Duration(86400) * time.Second))

	// Store the 2FA information in the storage
	info := &twofa.Info{
		ContextKey:     "stdlibrary_benchmark1234",
		Secret:         secret,
		CookieValue:    cookieValue,
		ExpirationTime: time.Time{},
	}
	infoJSON, _ := twoFAConfig.JSONMarshal(info)
	err := store.Set("stdlibrary_benchmark1234", infoJSON, 0)
	if err != nil {
		b.Fatalf("Failed to store 2FA information: %v", err)
	}

	// Create a request with the valid cookie
	req := httptest.NewRequest(fiber.MethodGet, "/?token="+token, nil)
	req.Header.Set(fiber.HeaderCookie, twoFAConfig.CookieName+"="+cookieValue)

	// Perform the initial request to generate and store the 2FA information
	resp, err := app.Test(req)
	if err != nil {
		b.Fatalf("Failed to perform initial request: %v", err)
	}
	defer resp.Body.Close()

	// Extract the generated cookie from the response
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == twoFAConfig.CookieName {
			cookieValue = cookie.Value
			break
		}
	}

	if cookieValue == "" {
		b.Fatalf("Failed to retrieve the generated cookie")
	}

	// Create a new request with the valid cookie
	req = httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set(fiber.HeaderCookie, twoFAConfig.CookieName+"="+cookieValue)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp, _ := app.Test(req)
		utils.AssertEqual(b, fiber.StatusOK, resp.StatusCode)
	}
}
