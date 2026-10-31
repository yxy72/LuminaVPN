package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ValidationError identifies a schema field, never the rejected private value.
// Array indexes are zero-based. JSON line/column positions are one-based bytes.
type ValidationError struct {
	Field   string
	Message string
	Line    int
	Column  int
}

func (e *ValidationError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%s (line %d, column %d): %s", e.Field, e.Line, e.Column, e.Message)
	}
	return e.Field + ": " + e.Message
}

func fieldError(field, message string) error {
	return &ValidationError{Field: field, Message: message}
}

func decodeError(data []byte, err error) error {
	detail := &ValidationError{Field: "policy", Message: "invalid policy JSON or unknown field"}
	var syntax *json.SyntaxError
	var valueType *json.UnmarshalTypeError
	var offset int64
	switch {
	case errors.As(err, &syntax):
		offset = syntax.Offset
	case errors.As(err, &valueType):
		offset = valueType.Offset
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		offset = int64(len(data)) + 1
	}
	if offset > 0 && offset <= int64(len(data))+1 {
		detail.Line, detail.Column = 1, 1
		for _, b := range data[:offset-1] {
			if b == '\n' {
				detail.Line, detail.Column = detail.Line+1, 1
			} else {
				detail.Column++
			}
		}
	}
	return detail
}
