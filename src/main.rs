
#![feature(macro_rules)]

extern crate "rust-crypto" as crypto;
extern crate serialize;

use crypto::digest::Digest;
use crypto::sha1::Sha1;
use serialize::base64::{Config, Standard, ToBase64};
use std::collections::TreeMap;
use std::fmt;
use std::io::{Acceptor, BufferedReader, IoError, IoResult, Listener, OtherIoError, Reader, TcpListener, TcpStream};
use std::num::FromPrimitive;
use std::vec::Vec;

macro_rules! some( ($e:expr,$none:expr) => (match $e { Some(e) => e, None => return $none } ))
macro_rules! tryWith( ($e:expr,$none:expr) => (match $e { Ok(x) => x, Err(_) => return $none } ))
macro_rules! genericError( ($msg:expr) => (Err(IoError { kind: OtherIoError, desc: $msg, detail: None })))

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
    let header_name = some!(header.next(), None);
    let header_value = some!(header.next(), None).trim_left();
    return Some(Header { 
      name: some!(from_str(header_name), None),
      value: some!(from_str(header_value), None)
    });
}

fn perform_handshake(mut stream: TcpStream) -> IoResult<()> {

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
        None => return genericError!("No challenge header"),
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
    
    stream.write(format_args!(fmt::format, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", challenge_response).as_bytes())

}

fn ws_send(mut stream: TcpStream, msg: &[u8]) -> IoResult<()> {

    try!(stream.write([129]));
        
    let len: uint = msg.len();
    let l1: u8 = some!(FromPrimitive::from_uint(len >> 24), genericError!("Conversion error"));
    let l2: u8 = some!(FromPrimitive::from_uint(len >> 16), genericError!("Conversion error"));
    let l3: u8 = some!(FromPrimitive::from_uint(len >>  8), genericError!("Conversion error"));
    let l4: u8 = some!(FromPrimitive::from_uint(len      ), genericError!("Conversion error"));
    
    try!(match len {
        _ if len <= 125 => 
            stream.write(&[l4]),
        _ if len > 125 && len <= 65535 => 
            stream.write(&[126u8, l3, l4]),
        _ => 
            // HMM, looks like really 8 bytes are required
            stream.write(&[127u8, l1, l2, l3, l4])
    });

    return stream.write(msg)
}

fn ws_recv(mut stream: TcpStream) -> IoResult<String> {
    
    let _text_type = try!(stream.read_byte());
    
    let len1 = 0x7F & try!(stream.read_byte());
    
    let length: uint = match len1 {
        _ if len1 <= 125 =>
            some!(FromPrimitive::from_u8(len1), genericError!("Conversion error")),
        _ =>
            return genericError!("TODO ws_recv len cases")
    };
    
    println!("Receiving message with {} bytes", length);
    
    let mut mask: [u8, ..4] = [0, ..4];
    try!(stream.read(mask));
    
    let mut data: Vec<u8> = try!(stream.read_exact(length));
    
    for i in range(0, length) {
        *data.get_mut(i) = data[i] ^ mask[i % 4];
    }
    
    let text = tryWith!(String::from_utf8(data), genericError!("Invalid unicode"));
    
    Ok(text)
    
}

fn handle_client(mut stream: TcpStream) -> IoResult<()> {

    println!("Handling client");
    
    try!(perform_handshake(stream.clone()));
    
    ws_send(stream.clone(), "Test message".as_bytes());
    
    loop {
        let msg = try!(ws_recv(stream.clone()));
        ws_send(stream.clone(), msg.as_bytes());
    }
    
    Ok(())
    
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

