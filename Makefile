export CGO_ENABLED=1
export GO111MODULE=off

build.providers.386: export GOOS=windows
build.providers.386: export GOARCH=386
build.providers.386: export CC=i686-w64-mingw32-gcc
build.providers.386:
	go build -o ./bin/providers-386.exe ./examples/providers/main.go
.PHONY: build.providers.386

build.providers.amd64: export GOOS=windows
build.providers.amd64: export GOARCH=amd64
build.providers.amd64: export CC=x86_64-w64-mingw32-gcc
build.providers.amd64:
	go build -o ./bin/providers-amd64.exe ./examples/providers/main.go
.PHONY: build.providers.amd64

build.providers.xp: export GOOS=windows
build.providers.xp: export GOARCH=386
build.providers.xp: export CC=i686-w64-mingw32-gcc
build.providers.xp:
	go1.10.8 build -tags winxp -o ./bin/providers-winxp.exe ./examples/providers/main.go
.PHONY: build.providers.xp

build.tracer.386: export GOOS=windows
build.tracer.386: export GOARCH=386
build.tracer.386: export CC=i686-w64-mingw32-gcc
build.tracer.386:
	go build -o ./bin/tracer-386.exe ./examples/tracer/main.go
.PHONY: build.tracer.386

build.tracer.amd64: export GOOS=windows
build.tracer.amd64: export GOARCH=amd64
build.tracer.amd64: export CC=x86_64-w64-mingw32-gcc
build.tracer.amd64:
	go build -o ./bin/tracer-amd64.exe ./examples/tracer/main.go
.PHONY: build.tracer.amd64

build.tracer.xp: export GOOS=windows
build.tracer.xp: export GOARCH=386
build.tracer.xp: export CC=i686-w64-mingw32-gcc
build.tracer.xp:
	go1.10.8 build -tags winxp -o ./bin/tracer-winxp.exe ./examples/tracer/main.go
.PHONY: build.tracer.xp