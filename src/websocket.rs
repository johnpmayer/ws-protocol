
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use serialize::base64::{Config, Standard, ToBase64};
use std::collections::TreeMap;
use std::fmt;
use std::io::{BufferedReader, IoError, IoResult, OtherIoError, Reader, TcpStream};
use std::num::FromPrimitive;
use std::vec::Vec;

macro_rules! some( ($e:expr,$none:expr) => (match $e { Some(e) => e, None => return $none } ))
macro_rules! tryWith( ($e:expr,$none:expr) => (match $e { Ok(x) => x, Err(_) => return $none } ))
macro_rules! genericError( ($msg:expr) => (Err(IoError { kind: OtherIoError, desc: $msg, detail: None })))

static WS_MAGIC_GUID : &'static str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub struct WebSocket {
    stream: TcpStream
}

struct HttpHeader {
    name: String,
    value: String
}

fn read_header(line: &str) -> Option<HttpHeader> {
    let mut header = line.trim_right().split_str(":");
    let header_name = some!(header.next(), None);
    let header_value = some!(header.next(), None).trim_left();
    return Some(HttpHeader { 
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
            local.push_str(WS_MAGIC_GUID);
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

impl WebSocket {

    pub fn new(stream: TcpStream) -> IoResult<WebSocket> {
        try!(perform_handshake(stream.clone()));
        Ok(WebSocket { stream: stream.clone() })
    }
    
    pub fn send(&mut self, msg: &[u8]) -> IoResult<()> {

        try!(self.stream.write([129]));
            
        let len: uint = msg.len();
        let l1: u8 = some!(FromPrimitive::from_uint(len >> 24), genericError!("Conversion error"));
        let l2: u8 = some!(FromPrimitive::from_uint(len >> 16), genericError!("Conversion error"));
        let l3: u8 = some!(FromPrimitive::from_uint(len >>  8), genericError!("Conversion error"));
        let l4: u8 = some!(FromPrimitive::from_uint(len      ), genericError!("Conversion error"));
        
        try!(match len {
            _ if len <= 125 => 
                self.stream.write(&[l4]),
            _ if len > 125 && len <= 65535 => 
                self.stream.write(&[126u8, l3, l4]),
            _ => 
                // HMM, looks like really 8 bytes are required
                self.stream.write(&[127u8, l1, l2, l3, l4])
        });

        return self.stream.write(msg)
    }

    pub fn recv(&mut self) -> IoResult<String> {
        
        let _text_type = try!(self.stream.read_byte());
        
        let len1 = 0x7F & try!(self.stream.read_byte());
        
        let length: uint = match len1 {
            _ if len1 <= 125 =>
                some!(FromPrimitive::from_u8(len1), genericError!("Conversion error")),
            _ if len1 == 126 => {
                    let mut l: [u8, ..2] = [0, ..2];
                    try!(self.stream.read(l));
                    let high: uint = some!(FromPrimitive::from_u8(l[0]), genericError!("Conversion error"));
                    let low: uint = some!(FromPrimitive::from_u8(l[1]), genericError!("Conversion error"));
                    (high << 8) | low
                }
            _ =>
                return genericError!("TODO message length > 65535")
        };
        
        println!("Receiving message with {} bytes", length);
        
        let mut mask: [u8, ..4] = [0, ..4];
        try!(self.stream.read(mask));
        
        let mut data: Vec<u8> = try!(self.stream.read_exact(length));
        
        for i in range(0, length) {
            *data.get_mut(i) = data[i] ^ mask[i % 4];
        }
        
        let text = tryWith!(String::from_utf8(data), genericError!("Invalid unicode"));
        
        Ok(text)
        
    }
}


