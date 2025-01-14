package http2string

import (
	"fmt"
	"reflect"
)

// 作者：limanman233
// 时间 2023/12/8 19:20
// 作用 ： http请求的封装

// DebugPrint 打印结构体字段值
func (h *Http2string) DebugPrint() {
	v := reflect.ValueOf(*h)
	t := reflect.TypeOf(*h)

	fmt.Println("Http2Json 结构体字段值:")
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)
		fmt.Printf("字段-%s-的值为: %v\n", field.Name, value.Interface())
	}
}
