package http2string

import (
	"net/http"
	"net/url"
)

type Option func(*Http2string)

// WithProxy 设置代理
func WithProxy(proxy string) Option {
	return func(o *Http2string) {
		if o.Client == nil {
			o.Client = &http.Client{}
		}
		// 校验 proxy 是否为有效的 URL
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			// 如果 proxy 不是有效的 URL，可以选择返回错误或使用默认行为
			return
		}

		// 设置代理
		o.Client.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	}
}

// WithHttpClient 设置httpclient
func WithHttpClient(httpClient *http.Client) Option {
	return func(o *Http2string) {
		o.Client = httpClient
	}
}
