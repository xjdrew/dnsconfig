package main

import (
	"fmt"

	"github.com/xjdrew/dnsconfig"
)

func main() {
	conf := dnsconfig.ReadDnsConfig()
	fmt.Printf("dnsconfig: %+v", conf)
}
