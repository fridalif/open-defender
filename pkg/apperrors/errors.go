package apperrors

import "fmt"

type CustomError struct {
	Module string
	Text   string
}

func (c *CustomError) Error() string {
	return fmt.Sprintf("%s: %s", c.Module, c.Text)
}
