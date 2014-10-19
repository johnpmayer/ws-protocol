
#![crate_id="rsfix#0.0"]
#![feature(macro_rules)]

use std::fmt;
use std::io::{BufferedReader, TcpListener, TcpStream, Acceptor, Listener, IoResult};

macro_rules! some( ($e:expr) => (match $e { Some(e) => e, None => return None } ))

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

    fn handle_client(stream: TcpStream) {
        println!("Handling client");
        
        let mut reader = BufferedReader::new(stream);
        
        let method = reader.read_line();
        
        loop {
            match reader.read_line() {
                Err(e) => {
                    println!("Read error: {}", e);
                    break
                },
                Ok(line) => {
                    match read_header(line.as_slice()) {
                        None => break,
                        Some(header) => println!("Header '{}'", header)
                    }
                }
            }
        }
        
        println!("Finished reading headers");
        
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

