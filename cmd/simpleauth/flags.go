package main

import (
	"flag"
)

type Flags struct {
	ConfigFile string
}

func flags() Flags {
	config := flag.String("config-file", "~/.simpleauth/config.toml", "path to configuration file")
	flag.Parse()
	return Flags{
		ConfigFile: *config,
	}
}
