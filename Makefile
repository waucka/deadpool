#GOFLAGS=-gcflags '-N -l'

GOFILES=main.go commonlib/commonlib.go openshift/openshift.go dns/route53/route53.go

all: linux osx windows

linux: build/linux-amd64/deadpool

osx: build/osx-amd64/deadpool

windows: build/win-amd64/deadpool.exe

# Linux Build
build/linux-amd64/deadpool: $(GOFILES)
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $@ github.com/waucka/deadpool

# OS X Build
build/osx-amd64/deadpool: $(GOFILES)
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -o $@ github.com/waucka/deadpool

# Windows Build
build/win-amd64/deadpool.exe: $(GOFILES)
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -o $@ github.com/waucka/deadpool

clean:
	rm -f build/linux-amd64/deadpool
	rm -f build/osx-amd64/deadpool
	rm -f build/win-amd64/deadpool.exe

.PHONY: all test clean deploy linux osx windows
