# Package: protocol

Implements the Docker Compose provider message format.

Compose runs a provider as a subprocess and reads its stdout as newline
delimited JSON. Every line must be an object carrying a "type" and a
"message" attribute. Any other byte written to stdout corrupts the stream,
so all diagnostics must be routed through an Emitter or sent to stderr.
