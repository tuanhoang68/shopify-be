package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

var (
	SHOPIFY_CLIENT_ID     = "SHOPIFY_CLIENT_ID"
	SHOPIFY_CLIENT_SECRET = "SHOPIFY_CLIENT_SECRET"
	APP_URL               = "http://localhost:3000"
)

// Lưu token tạm trong RAM
var tokenStore = make(map[string]string)

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/auth/callback", callbackHandler)
	http.HandleFunc("/tokens", tokensHandler)
	http.HandleFunc("/products", productsHandler)

	fmt.Println("Server chạy ở http://localhost:3000 ...")
	log.Fatal(http.ListenAndServe(":3000", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`
        <h1>Shopify OAuth Demo</h1>
        <p>Đi đến /auth?shop=your-dev-store.myshopify.com để cài app</p>
    `))
}

// Bước 1: Điều hướng đến Shopify OAuth
func authHandler(w http.ResponseWriter, r *http.Request) {
	shop := r.URL.Query().Get("shop")
	if shop == "" {
		http.Error(w, "Missing shop parameter", http.StatusBadRequest)
		return
	}

	redirectURL := fmt.Sprintf("https://%s/admin/oauth/authorize?client_id=%s&scope=read_products&redirect_uri=%s/auth/callback",
		shop, SHOPIFY_CLIENT_ID, APP_URL)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// Bước 2: Shopify trả về code → đổi token
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	shop := r.URL.Query().Get("shop")
	code := r.URL.Query().Get("code")

	if shop == "" || code == "" {
		http.Error(w, "Missing shop or code", http.StatusBadRequest)
		return
	}

	// Gửi request lấy access token
	tokenURL := fmt.Sprintf("https://%s/admin/oauth/access_token", shop)

	resp, err := http.PostForm(tokenURL, url.Values{
		"client_id":     {SHOPIFY_CLIENT_ID},
		"client_secret": {SHOPIFY_CLIENT_SECRET},
		"code":          {code},
	})
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		http.Error(w, "Invalid token response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Lưu token vào RAM
	tokenStore[shop] = tokenResp.AccessToken

	// Trả HTML kết quả + link lấy sản phẩm
	html := fmt.Sprintf(`
		<h2>Install thành công!</h2>
		<p>Shop: %s</p>
		<p>Access Token: %s</p>

		<p><a href="/tokens">Xem tất cả tokens</a></p>
		<p><a href="/products?shop=%s">Lấy danh sách products</a></p>
	`, shop, tokenResp.AccessToken, shop)

	w.Write([]byte(html))
}

// Xem tất cả tokens (debug)
func tokensHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(tokenStore)
}

// Lấy danh sách sản phẩm
func productsHandler(w http.ResponseWriter, r *http.Request) {
	shop := r.URL.Query().Get("shop")
	if shop == "" {
		http.Error(w, "Missing shop parameter", http.StatusBadRequest)
		return
	}

	token, ok := tokenStore[shop]
	if !ok {
		http.Error(w, "Token not found for this shop", http.StatusNotFound)
		return
	}

	// Call Shopify Admin API
	apiURL := fmt.Sprintf("https://%s/admin/api/2024-01/products.json", shop)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		http.Error(w, "Request error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Add("X-Shopify-Access-Token", token)
	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		http.Error(w, "API error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}
