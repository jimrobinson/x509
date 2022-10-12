x509: *.go
	go build .

deb: x509
	nfpm package -p deb

build:
	cd build-env; docker build -t x509-build-env .
	docker run --rm \
		-v "$(CURDIR)":/go/src/x509 \
		-w /go/src/x509 \
		x509-build-env make deb

clean:
	rm -f x509 x509_*.deb
