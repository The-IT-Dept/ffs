// Command sleeper is the end-to-end suite's workload: it blocks until SIGTERM or SIGINT, then exits 0.
package main

import (
	"os"
	"os/signal"
	"syscall"
)

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, os.Interrupt)
	<-c
}
