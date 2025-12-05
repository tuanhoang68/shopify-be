package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/joho/godotenv"
)

var (
	shopTokens = struct {
		sync.RWMutex
		m map[string]string
	}{m: make(map[string]string)}
)

func main() {
	// load .env
	_ = godotenv.Load()

	apiKey := os.Getenv("SHOPIFY_API_KEY")
	apiSecret := os.Getenv("SHOPIFY_API_SECRET")
	appHost := os.Getenv("APP_HOST") // e.g. https://abcd.ngrok.io or https://your-domain.com
	if apiKey == "" || apiSecret == "" || appHost == "" {
		log.Fatal("Please set SHOPIFY_API_KEY, SHOPIFY_API_SECRET, APP_HOST in env")
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		handleAuth(w, r, apiKey, appHost)
	})
	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		handleAuthCallback(w, r, apiKey, apiSecret)
	})
	http.HandleFunc("/api/products", handleProducts)

	addr := ":8080"
	log.Printf("BE listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<h2>Shopify App Backend (Demo)</h2>
<p>To install, open this URL (replace <em>{shop}</em>):</p>
<pre>%s/auth?shop={shop}.myshopify.com</pre>
<p>Example: <a href="%s/auth?shop=your-store.myshopify.com">%s/auth?shop=your-store.myshopify.com</a></p>
`, r.Host, r.Host, r.Host)
}

// /auth?shop=the-shop.myshopify.com
func handleAuth(w http.ResponseWriter, r *http.Request, apiKey, appHost string) {
	shop := r.URL.Query().Get("shop")
	if shop == "" {
		http.Error(w, "missing shop", http.StatusBadRequest)
		return
	}

	// create state (simple random string). For demo we won't store persistent state
	state := "statedemo" // in production generate random and store in cookie/session
	redirectURI := fmt.Sprintf("%s/auth/callback", appHost)

	scope := "read_products,write_products" // adjust scopes
	installURL := fmt.Sprintf("https://%s/admin/oauth/authorize?client_id=%s&scope=%s&redirect_uri=%s&state=%s",
		shop, apiKey, scope, redirectURI, state)

	http.Redirect(w, r, installURL, http.StatusFound)
}

// /auth/callback?code=...&shop=...&state=...
func handleAuthCallback(w http.ResponseWriter, r *http.Request, apiKey, apiSecret string) {
	shop := r.URL.Query().Get("shop")
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if shop == "" || code == "" {
		http.Error(w, "missing params", http.StatusBadRequest)
		return
	}
	_ = state // for demo skip verifying

	// Exchange code for access token
	url := fmt.Sprintf("https://%s/admin/oauth/access_token", shop)
	body := map[string]string{
		"client_id":     apiKey,
		"client_secret": apiSecret,
		"code":          code,
	}
	bts, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(bts))
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		http.Error(w, "token exchange failed: "+string(respBody), http.StatusInternalServerError)
		return
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		http.Error(w, "invalid token response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// store token in memory (demo)
	shopTokens.Lock()
	shopTokens.m[shop] = parsed.AccessToken
	shopTokens.Unlock()

	// After successful install, redirect to your app FE (Shopify will call with host param if embedded)
	// We redirect to frontend app url (APP_HOST). Add ?shop=... so FE knows the shop
	appHost := os.Getenv("APP_HOST")
	redirectTo := fmt.Sprintf("%s?shop=%s", appHost, shop)
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

// /api/products?shop=...
// Expect Authorization: Bearer <session-token> from FE. For demo, we only check that a token exists for the shop.
func handleProducts(w http.ResponseWriter, r *http.Request) {
	shop := r.URL.Query().Get("shop")
	if shop == "" {
		http.Error(w, "missing shop query", http.StatusBadRequest)
		return
	}

	// Validate that shop is installed (has an access token in memory)
	shopTokens.RLock()
	_, ok := shopTokens.m[shop]
	shopTokens.RUnlock()
	if !ok {
		http.Error(w, "shop not installed", http.StatusUnauthorized)
		return
	}

	// (In production) verify session token from Authorization header. For demo we skip deep verification.
	// Return fake products
	fakeProducts := []map[string]interface{}{
		{"id": 1, "title": "Demo Product A", "price": "99.00"},
		{"id": 2, "title": "Demo Product B", "price": "149.00"},
	}

	resp := map[string]interface{}{
		"products": fakeProducts,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
