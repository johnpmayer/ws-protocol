
extern crate openssl;

use std::io::{TcpListener, TcpStream};
use std::io::{Acceptor, Listener};

fn main() {

    let listener = TcpListener::bind("0.0.0.0", 9000);

    let mut acceptor = listener.listen();

    fn handle_client(stream: TcpStream) {
        println!("Handling client");
    }

    /*
     * Accept Loop
     */

    for stream_result in acceptor.incoming() {
        match stream_result {
            Err(e) => { 
                println!("Accept error: {}", e); 
            }
            Ok(stream) => spawn(proc() {
                handle_client(stream)
            })
        }
    }
}
