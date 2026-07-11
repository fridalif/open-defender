package main

import (
	"log"
	"open-defender/pkg/app"
	"os"
)

func main() {
	if os.Geteuid() != 0 {
		log.Fatalln("failed to run programm: you must be a superuser")
	}
	app := app.New()
	err := app.Initialize()
	if err != nil {
		log.Fatalln(err)
	}
	err = app.Run()
	if err != nil {
		log.Fatalln(err)
	}
}
