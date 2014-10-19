
#![feature(macro_rules)]

extern crate "rust-crypto" as crypto;
extern crate serialize;

use crypto::digest::Digest;
use crypto::sha1::Sha1;
use serialize::base64::{Config, Standard, ToBase64};
use std::collections::TreeMap;
use std::fmt;
use std::io::{BufferedReader, TcpListener, TcpStream, Acceptor, Listener, IoResult};

macro_rules! some( ($e:expr) => (match $e { Some(e) => e, None => return None } ))

static WS_GUID : &'static str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn main() {
  match run() {
    Ok(_) => return,
    Err(e) => {
      println!("Got error {}", e);
    }
  }
}

struct Header {
    name: String,
    value: String
}

impl fmt::Show for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Header({} => {})", self.name, self.value)
    }
}

fn read_header(line: &str) -> Option<Header> {
    let mut header = line.trim_right().split_str(":");
    let header_name = some!(header.next());
    let header_value = some!(header.next()).trim_left();
    return Some(Header { 
      name: some!(from_str(header_name)),
      value: some!(from_str(header_value))
    });
}


fn run() -> IoResult<int> {

    let listener = TcpListener::bind("0.0.0.0", 9000);

    let mut acceptor = listener.listen();

    fn handle_client(mut stream: TcpStream) {
        println!("Handling client");
        
        let mut reader = BufferedReader::new(stream.clone());
        
        let _method = reader.read_line();
        
        let mut headers = TreeMap::new();
        
        loop {
            match reader.read_line() {
                Err(e) => {
                    println!("Read error: {}", e);
                    break
                },
                Ok(line) => {
                    match read_header(line.as_slice()) {
                        None => break,
                        Some(header) => {
                            println!("Header '{}'", header);
                            headers.insert(header.name, header.value);
                        }
                    }
                }
            }
        }
        
        let key = String::from_str("Sec-WebSocket-Key");
        
        // TODO : validate "Origin" header. important for security
        
        let challenge_response: String = match headers.find(&key) {
            None => return println!("No challenge header"),
            Some(challenge) => {
                let mut hasher = Sha1::new();
                let mut local = challenge.clone();
                local.push_str(WS_GUID);
                println!("Using {}", local);
                hasher.input(local.as_bytes());
                let mut output = [0, ..20];
                hasher.result(output);
                output.to_base64(Config {
                    char_set: Standard,
                    pad: true,
                    line_length: None
                })
            }
        };
        
        println!("Using {}", challenge_response);
        
        let _res = stream.write(format_args!(fmt::format, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", challenge_response).as_bytes());
        
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
    
    return Ok(0);
}

