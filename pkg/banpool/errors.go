package banpool

import "errors"

var (
	ErrCantCreateDatabaseDir = errors.New("cant create database directory")
	ErrCantOpenDatabase      = errors.New("cant open database")
	ErrCantCreateTable       = errors.New("cant create bans table")
	ErrCantAddBan            = errors.New("cant add ban")
	ErrCantGetBan            = errors.New("cant get ban")
	ErrCantGetBannedIPs      = errors.New("cant get banned ips")
	ErrCantUpdateBan         = errors.New("cant update ban")
	ErrCantDeleteBan         = errors.New("cant delete ban")
	ErrBanNotFound           = errors.New("ban not found")
	ErrInvalidIP             = errors.New("invalid ip address")
	ErrCantBanIP             = errors.New("cant ban ip")
	ErrCantUnbanIP           = errors.New("cant unban ip")
)
