export CGO_ENABLED=1
export GO111MODULE=off

build.windows.amd64: export GOOS=windows
build.windows.amd64: export GOARCH=amd64
build.windows.amd64: export CC=x86_64-w64-mingw32-gcc
build.windows.amd64:
	go build -o ./bin/tracer-amd64.exe ./examples/tracer/main.go
.PHONY: build.windows.amd64

build.windows.386: export GOOS=windows
build.windows.386: export GOARCH=386
build.windows.386: export CC=i686-w64-mingw32-gcc
build.windows.386:
	go build -o ./bin/tracer-386.exe ./examples/tracer/main.go
.PHONY: build.windows.386

# Lowest version for support windows xp is go1.10.
build.windows.xp: export GOOS=windows
build.windows.xp: export GOARCH=386
build.windows.xp: export CC=i686-w64-mingw32-gcc
build.windows.xp:
	go1.10.8 build -tags winxp -o ./bin/tracer-xp.exe ./examples/tracer/main.go
.PHONY: build.windows.xp