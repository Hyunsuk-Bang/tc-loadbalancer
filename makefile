gen:
	go generate internal/loadbalancer/generate.go

build: gen
	go build -o lb .

run-bpf: build
	sudo ./lb -bpf -debug

run-socket: build
	sudo ./lb -debug

clean:
	rm -rf *.o