use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::sync::mpsc::{Receiver, Sender};

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 512;

fn sleep() {
    thread::sleep(::std::time::Duration::from_millis(100));
}

fn main() {
    let server = TcpListener::bind(LOCAL).expect("Listener failed to bind");
    server.set_nonblocking(true).expect("failed to initialize non-blocking");

    let mut clients = vec![];
    let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
    loop {
        if let Ok((mut socket, addr)) = server.accept() {
            println!("Client {} connected", addr);

            let tx = tx.clone();
            clients.push(socket.try_clone().expect("failed to clone client"));

            thread::spawn(move || loop {
                let mut buff = vec![0; MSG_SIZE];

                match socket.read_exact(&mut buff) {
                    Ok(_) => {
                        let total_len = u32::from_le_bytes(buff[0..4].try_into().unwrap()) as usize;
                        if total_len > MSG_SIZE {
                            // read the rest of the message
                            let mut rest = vec![0; total_len - MSG_SIZE];
                            match socket.read_exact(&mut rest) {
                                Ok(_) => {
                                    buff.extend(rest);
                                },
                                Err(e) => {
                                    println!("failed to read rest of message: {:?}", e);
                                    break;
                                }
                            }
                        }
                        let msg = buff.clone();

                        println!("{}: {:?}", addr, msg);
                        tx.send(msg).expect("failed to send msg to rx");
                    }, 
                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
                    Err(_) => {
                        println!("closing connection with: {}", addr);
                        break;
                    }
                }

                sleep();
            });
        }

        if let Ok(msg) = rx.try_recv() {
            clients = clients.into_iter().filter_map(|mut client| {
                let mut buff = msg.clone();
                let total_len = u32::from_le_bytes(buff[0..4].try_into().unwrap()) as usize;
                let packet_len = std::cmp::max(total_len, MSG_SIZE);
                buff.resize(packet_len, 0);

                client.write_all(&buff).map(|_| client).ok()
            }).collect::<Vec<_>>();
        }

        sleep();
    }
}
