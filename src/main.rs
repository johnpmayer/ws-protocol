
use std::io::{TcpListener, TcpStream};
use std::io::{Acceptor, Listener};

fn main() {

    let listener = TcpListener::bind("0.0.0.0", 9000);

    let mut acceptor = listener.listen();

    fn handle_client(mut stream: TcpStream) {
        println!("Handling client from {}", stream.peer_name());
    }

    for stream in acceptor.incoming() {
        match stream {
            Err(e) => { 
                println!("{}", e); 
            }
            Ok(stream) => spawn(proc() {
                handle_client(stream)
            })
        }
    }

    drop(acceptor);

}
