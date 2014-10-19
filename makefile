
all: exe

clean:
	cargo clean

run: exe
	cargo run

exe: target\ws-server.exe

target\ws-server.exe: src\main.rs
	cargo build