package main

import (
	"fmt"
	"log"
	"open-defender/pkg/app"
	"open-defender/pkg/config"
	"os"
)

func main() {
	os.Exit(run(os.Args, app.New, os.Geteuid() == 0))
}

func run(args []string, newApp func() app.App, isRoot bool) int {
	runConfig, err := config.ParseArgs(args)
	if err != nil {
		log.Println(err)
		fmt.Print(config.Usage)
		return 1
	}

	if runConfig.Help {
		fmt.Print(config.Usage)
		return 0
	}

	application := newApp()

	if runConfig.Test {
		if err := application.TestConfig(); err != nil {
			log.Println(err)
			return 1
		}
		return 0
	}

	if runConfig.Status {
		if err := application.Status(); err != nil {
			log.Println(err)
			return 1
		}
		return 0
	}

	if !isRoot {
		log.Println("failed to run programm: you must be a superuser")
		return 1
	}

	if runConfig.Update {
		if err := application.Update(); err != nil {
			log.Println(err)
			return 1
		}
		return 0
	}

	if runConfig.Restart {
		if err := application.Restart(); err != nil {
			log.Println(err)
			return 1
		}
		return 0
	}

	if err := application.Initialize(); err != nil {
		log.Println(err)
		return 1
	}

	if runConfig.Install {
		if err := application.Install(); err != nil {
			log.Println(err)
			return 1
		}
		return 0
	}

	application.Run()
	return 0
}
