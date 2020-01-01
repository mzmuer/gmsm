# gmsm
支持除标准椭圆曲线以外的国密sm2证书解析

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

var sm2Cert = `-----BEGIN CERTIFICATE-----
MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG
EwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQw
MzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVO
UkNBQzEPMA0GA1UEAwwGUk9PVENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE
MPCca6pmgcchsTf2UnBeL9rtp4nw+itk1Kzrmbnqo05lUwkwlWK+4OIrtFdAqnRT
V7Q9v1htkv42TsIutzd126NdMFswHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti
W/CXdlgwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFEwysZfZ
MxvEpgXBxuWLYlvwl3ZYMAwGCCqBHM9VAYN1BQADSAAwRQIgG1bSLeOXp3oB8H7b
53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xI
pDoiVhsLwg==
-----END CERTIFICATE-----`

func main(){
	block, _ := pem.Decode([]byte(strings.TrimSpace(sm2Cert)))
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