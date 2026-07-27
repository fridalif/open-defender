package connector

import "errors"

var (
	ErrSomethingWrongInWriteChanel = errors.New("SomethingWrongInWriteChanel")
	ErrWebscoketIsNull             = errors.New("Websocket is Null")
	ErrBadEndpointKey              = errors.New("cant parse endpoint rsa public key")
	ErrCantDialEndpoint            = errors.New("cant dial endpoint")
	ErrUnexpectedMessage           = errors.New("unexpected message")
	ErrUnsupportedVersion          = errors.New("unsupported protocol version")
	ErrBadConfigPayload            = errors.New("cant parse config payload")
)
