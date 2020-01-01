# gmsm
支持除标准以外的国密sm2证书解析

## 安装
使用 `go get` 下载安装 SDK

```sh
$ go get -u github.com/mzmuer/gmsm
```
## 快速开始
```go
package main

import (
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/mzmuer/gmsm/x509"
)


func main(){
	block, _ := pem.Decode("certificate")
	if block == nil {
		panic(fmt.Errorf("failed to parse certificate PEM"))
	}

	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(c)
	}
}
```