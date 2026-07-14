package updater

import "errors"

var (
	ErrFetchVersion    = errors.New("failed to fetch the latest version")
	ErrEmptyVersion    = errors.New("version must not be empty")
	ErrInvalidVersion  = errors.New("version may only hold letters, digits, dots, dashes and underscores")
	ErrUnknownArch     = errors.New("architecture is not one of the released ones")
	ErrReadInput       = errors.New("failed to read the input")
	ErrDownloadRelease = errors.New("failed to download the release")
	ErrReleaseNotFound = errors.New("the release is not there")
	ErrWriteBinary     = errors.New("failed to write the downloaded binary")
	ErrReplaceBinary   = errors.New("failed to replace the installed binary")
)
