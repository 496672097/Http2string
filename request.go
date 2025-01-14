package Http2string

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-resty/resty/v2"
)

//作者：limanman233
//时间 2024/11/20 17:20
//作用 ： http请求的封装

// Http2string http请求的结构体
type Http2string struct {
	Method      string
	Url         string
	Headers     map[string]string
	Body        []byte
	Client      *http.Client
	Certcerpath string  // 证书路径
	Certkeypath string  // 证书路径
	Erros       []error // 错误信息
	NeedCert    bool    // 是否需要证书
}

// 设置默认值client
func (h *Http2string) setDefaultInfo() {
	if h.Method == "" {
		h.Method = "GET"
	}
	if h.Headers == nil {
		h.Headers = make(map[string]string)
		h.Headers["Content-Type"] = "application/json"
		h.Headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0"
	}
	// 创建一个自定义的http.Transport
	if h.Client == nil {
		transCfg := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				},

				CurvePreferences: []tls.CurveID{
					tls.CurveP256,
					tls.CurveP384,
					tls.CurveP521,
				},
				PreferServerCipherSuites: true,
				ClientAuth:               tls.RequireAndVerifyClientCert,
			}, // 忽略证书验证
		}
		if h.NeedCert {
			cer, err := loadClientCertificate()
			if err == nil {
				transCfg.TLSClientConfig.Certificates = []tls.Certificate{cer}
			}
		}
		h.Client = &http.Client{
			Transport: transCfg,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // 不跟随重定向
			},
		}
	}

}

// 加载客户端证书的辅助函数
func loadClientCertificate() (tls.Certificate, error) {
	// 检查并创建certs文件夹
	certsDir := "certs"
	if _, err := os.Stat(certsDir); os.IsNotExist(err) {
		err := os.MkdirAll(certsDir, os.ModePerm)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("创建certs文件夹失败: %v", err)
		}
	}
	// 加载客户端证书
	certPath := filepath.Join(certsDir, "client.crt")
	keyPath := filepath.Join(certsDir, "client.key")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("加载客户端证书失败: %v", err)
	}
	return cert, nil
}

// httpRequest creates an HTTP request and returns the response headers, body, and any error encountered.
// @param method: The HTTP method to use (GET, POST, PUT, DELETE, etc.)
// @param headers: The HTTP headers to send with the request
// @param bodyData: The body data to send with the request
// @return respHeaders: 返回的header[string]string
// @return respBody: 返回的body
// @return duration: int 响应时间
// @return err:  错误信息
func (h *Http2string) HttpRequest(opts ...Option) (respHeaders map[string][]string, respBody []byte, duration time.Duration, err error) {
	h.setDefaultInfo()

	// 应用传递的选项
	for _, opt := range opts {
		opt(h)
	}

	// 创建 Resty 客户端
	client := resty.NewWithClient(h.Client)
	for header := range h.Headers {
		client.SetHeader(header, h.Headers[header])
	}

	// 创建请求
	req := client.R().
		SetHeaders(h.Headers).
		SetBody(h.Body)

	// 记录开始时间
	startTime := time.Now()

	// 发送请求并获取响应
	var resp *resty.Response
	switch h.Method {
	case "GET":
		resp, err = req.Get(h.Url)
	case "POST":
		resp, err = req.Post(h.Url)
	case "PUT":
		resp, err = req.Put(h.Url)
	case "DELETE":
		resp, err = req.Delete(h.Url)
	default:
		err = fmt.Errorf("unsupported HTTP method: %s", h.Method)
		return nil, nil, 0, err
	}

	// 记录结束时间
	duration = time.Since(startTime)
	// 检查错误
	if err != nil {
		return nil, nil, duration, err
	}

	// 获取响应头信息和响应体
	respHeaders = resp.Header()
	respBody = resp.Body()

	return respHeaders, respBody, duration, nil
}
