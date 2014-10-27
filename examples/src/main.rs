
extern crate ws;

use std::io::{Acceptor, IoResult, Listener, TcpListener, TcpStream};
use ws::websocket::WebSocket;

fn handle_client(stream: TcpStream) -> IoResult<()> {

    println!("Handling client");
    
    let mut ws = try!(WebSocket::new(stream));
    
    try!(ws.send("Test message".as_bytes()));
    
    loop {
        let msg = try!(ws.recv());
        try!(ws.send(msg.as_bytes()));
    }
    
}

fn run() -> IoResult<()> {

    let listener = TcpListener::bind("0.0.0.0", 9000);

    let mut acceptor = listener.listen();

    for stream_result in acceptor.incoming() {
        
        match stream_result {
            Err(e) => { 
                println!("Accept error: {}", e); 
            }
            Ok(stream) => spawn(proc() {
                match handle_client(stream) {
                    Ok(()) => println!("Client quit without error"),
                    Err(e) => println!("Client exited with error: {}", e)
                };
            })
        }
    }
    
    return Ok(());
}

fn main() {
  match run() {
    Ok(_) => return,
    Err(e) => {
      println!("Got error {}", e);
    }
  }
}
