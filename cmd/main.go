package main

import (
	"fmt"
	"log"
	"open-defender/pkg/app"
	"open-defender/pkg/config"
	"os"
)

func main() {
	runConfig, err := config.ParseArgs(os.Args)
	if err != nil {
		log.Println(err)
		fmt.Print(config.Usage)
		os.Exit(1)
	}

	if runConfig.Help {
		fmt.Print(config.Usage)
		return
	}

	app := app.New()

	if runConfig.Test {
		if err := app.TestConfig(); err != nil {
			log.Fatalln(err)
		}
		return
	}

	if runConfig.Status {
		if err := app.Status(); err != nil {
			log.Fatalln(err)
		}
		return
	}

	if os.Geteuid() != 0 {
		log.Fatalln("failed to run programm: you must be a superuser")
	}

	if runConfig.Update {
		if err := app.Update(); err != nil {
			log.Fatalln(err)
		}
		return
	}

	if runConfig.Restart {
		if err := app.Restart(); err != nil {
			log.Fatalln(err)
		}
		return
	}

	err = app.Initialize()
	if err != nil {
		log.Fatalln(err)
	}

	if runConfig.Install {
		err = app.Install()
		if err != nil {
			log.Fatalln(err)
		}
		return
	}

	app.Run()
}
