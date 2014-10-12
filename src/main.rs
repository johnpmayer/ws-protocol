
extern crate openssl;

use std::io::{TcpListener, TcpStream};
use std::io::{Acceptor, Listener};
use std::io::fs::{PathExtensions};
use openssl::x509::{PEM};
use openssl::ssl::{SslContext, Tlsv1, SslStream};

fn main() {

    let listener = TcpListener::bind("0.0.0.0", 9000);

    let mut acceptor = listener.listen();

    fn handle_client(mut stream: SslStream<TcpStream>) {
        println!("Handling secure client");
    }

    match SslContext::new(Tlsv1) {
        Err(e) => {
            println!("SslContext error: {}", e);
        }
        Ok(mut ctx) => { 

            ctx.set_CA_file(&Path::new(""));
            ctx.set_certificate_file(&Path::new(""), PEM);

            /*
             * Accept Loop
             */

            for stream_result in acceptor.incoming() {
                match stream_result {
                    Err(e) => { 
                        println!("Accept error: {}", e); 
                    }
                    Ok(mut stream) => spawn(proc() {
                        println!("Securing client from {}", stream.peer_name());
                        let ssl_result = SslStream::new(&ctx, stream);
                        match ssl_result {
                            Err(e) => {
                                println!("Ssl error: {}", e);
                            }
                            Ok(secure_stream) => {
                                handle_client(secure_stream)
                            }
                        }
                    })
                }
            }

            drop(acceptor);

        }
    };
}
