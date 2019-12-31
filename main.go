package main

import (
	"fmt"
	"flag"
)

func main() {
	var (
		container = flag.String("container", "","only trace newly created containers")
		bufpages = flag.Int("buf-pages", 1, "number of pages for perf buffer, defaults to %(default)s")

		ebpf = flag.Bool("ebpf", false, "")

		jsonFormat = flag.Bool("json", false, "save events in json format")

		listEnable = flag.Bool("list", false, "save events in json format")

		eventsToTrace = flag.String("events-to-trace", "", "trace only the specified events and syscalls (default: trace all)")

		showSysCall = flag.Bool("show-syscall", false, "show syscall name in kprobes")
	)

	flag.Parse()


}
