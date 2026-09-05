// Package protocol implements the Docker Compose provider message format:
// newline delimited JSON on stdout, one object per line.
package protocol

import (
	"encoding/json"
	"fmt"
	"io"
)

// Message types understood by Compose.
const (
	typeInfo      = "info"
	typeError     = "error"
	typeDebug     = "debug"
	typeRawSetEnv = "rawsetenv"
)

type message struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Emitter writes protocol messages to a stream.
type Emitter struct {
	enc *json.Encoder
	err error
}

// New returns an Emitter writing to w, which is os.Stdout in production.
func New(w io.Writer) *Emitter {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Emitter{enc: enc}
}

// Info reports a status update, rendered by Compose as the service state.
func (e *Emitter) Info(format string, args ...any) {
	e.emit(typeInfo, fmt.Sprintf(format, args...))
}

// Debug reports detail Compose logs without touching the service status line.
func (e *Emitter) Debug(format string, args ...any) {
	e.emit(typeDebug, fmt.Sprintf(format, args...))
}

// Error reports a failure reason for the service.
func (e *Emitter) Error(format string, args ...any) {
	e.emit(typeError, fmt.Sprintf(format, args...))
}

// RawSetEnv injects value under name. The value is never format expanded.
func (e *Emitter) RawSetEnv(name, value string) {
	e.emit(typeRawSetEnv, name+"="+value)
}

// Err reports the first write failure, if any.
func (e *Emitter) Err() error { return e.err }

// Emit writes a single protocol line. The message body is formatted first and
// then JSON encoded, so values containing quotes, backslashes or newlines
// cannot break the stream.
func (e *Emitter) emit(kind, body string) {
	if e.err != nil {
		return
	}
	e.err = e.enc.Encode(message{Type: kind, Message: body})
}
