FROM golang:bullseye

RUN go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

WORKDIR /go/src/x509
RUN nfpm --help
