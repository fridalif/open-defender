package main

import (
	"log"
	"open-defender/pkg/app"
)

func main() {
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
