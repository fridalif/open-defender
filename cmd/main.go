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

	if os.Geteuid() != 0 {
		log.Fatalln("failed to run programm: you must be a superuser")
	}
	app := app.New()
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
