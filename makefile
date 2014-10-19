
all: run

clean:
	cargo clean

run: exe
	cargo run --verbose

exe: target\ws-server.exe

target\ws-server.exe: src\main.rs
	cargo build