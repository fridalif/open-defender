package connector

import "errors"

var (
	ErrSomethingWrongInWriteChanel = errors.New("SomethingWrongInWriteChanel")
	ErrWebscoketIsNull             = errors.New("Websocket is Null")
)
