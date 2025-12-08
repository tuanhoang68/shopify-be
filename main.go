package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
)

var (
	SHOPIFY_CLIENT_ID     = "f3b6cde13bc22652403e31ab2e5f24b9"
	SHOPIFY_CLIENT_SECRET = "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"

	// Map lưu token in-memory
	tokenStore = map[string]string{}
)

func randomState() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	r := gin.Default()

	// ============================
	// 1. BẮT ĐẦU OAUTH
	// ============================
	r.GET("/auth", func(c *gin.Context) {
		shop := c.Query("shop")
		if shop == "" {
			c.String(400, "Thiếu tham số shop: ?shop=yourstore.myshopify.com")
			return
		}

		state := randomState()
		redirectUri := "http://localhost:3000/auth/callback"

		installUrl := fmt.Sprintf(
			"https://%s/admin/oauth/authorize?client_id=%s&scope=read_products,write_products&redirect_uri=%s&state=%s",
			shop,
			SHOPIFY_CLIENT_ID,
			redirectUri,
			state,
		)

		c.Redirect(http.StatusFound, installUrl)
	})

	// ============================
	// 2. NHẬN CODE VÀ LẤY TOKEN
	// ============================
	r.GET("/auth/callback", func(c *gin.Context) {
		shop := c.Query("shop")
		code := c.Query("code")

		if shop == "" || code == "" {
			c.String(400, "Thiếu shop hoặc code")
			return
		}

		client := resty.New()
		resp, err := client.R().
			SetHeader("Content-Type", "application/json").
			SetBody(map[string]interface{}{
				"client_id":     SHOPIFY_CLIENT_ID,
				"client_secret": SHOPIFY_CLIENT_SECRET,
				"code":          code,
			}).
			Post(fmt.Sprintf("https://%s/admin/oauth/access_token", shop))

		if err != nil {
			c.String(500, "Lỗi gọi Shopify API: %v", err)
			return
		}

		var data struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(resp.Body(), &data); err != nil {
			c.String(500, "Lỗi đọc response: %v", err)
			return
		}

		// Lưu token vào map
		tokenStore[shop] = data.AccessToken

		c.Header("Content-Type", "text/html")
		c.String(200, `
			<h2>Install thành công!</h2>
			<p>Shop: %s</p>
			<p>Access Token: %s</p>
			<p><a href="/tokens">Xem tất cả tokens</a></p>
			<p><a href="/products?shop=%s">Lấy danh sách products</a></p>
		`, shop, data.AccessToken)
	})

	// ============================
	// 3. XEM TOÀN BỘ TOKEN
	// ============================
	r.GET("/tokens", func(c *gin.Context) {
		c.JSON(200, tokenStore)
	})

	fmt.Println("Server chạy tại http://localhost:3000")
	r.Run(":3000")
}

// Lấy danh sách products
func productsHandler(w http.ResponseWriter, r *http.Request) {
	shop := r.URL.Query().Get("shop")
	if shop == "" {
		http.Error(w, "Missing shop parameter", http.StatusBadRequest)
		return
	}

	token, ok := tokenStore[shop]
	if !ok {
		http.Error(w, "Token not found for shop", http.StatusNotFound)
		return
	}

	url := fmt.Sprintf("https://%s/admin/api/2024-01/products.json", shop)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	req.Header.Add("X-Shopify-Access-Token", token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}
