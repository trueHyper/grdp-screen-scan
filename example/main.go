package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"github.com/tomatome/grdp/glog"
)

func main() {	
	/* ---set log--- */
	glog.SetLevel(glog.INFO)
	glog.SetLogger(log.New(os.Stdout, "", 0))
	
	if len(os.Args) < 2 {
		fmt.Println("Using: go run example.go <addr:port>")
		return
	}
	socket := os.Args[1]
	
	runtime.GOMAXPROCS(runtime.NumCPU())
	data(socket)
}