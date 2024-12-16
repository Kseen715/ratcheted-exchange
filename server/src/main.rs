use std::io::{ ErrorKind, Read, Write };
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::sync::mpsc::{ Receiver, Sender };
use std::time::SystemTime;
use std::net::TcpStream;
use chrono::{ DateTime, Utc };

// Add these struct definitions at the top
struct Client {
    socket: TcpStream,
    connected_at: SystemTime,
}

struct Message {
    data: Vec<u8>,
    timestamp: SystemTime,
}

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 512;

fn sleep() {
    thread::sleep(::std::time::Duration::from_millis(100));
}

fn main() {
    let server = TcpListener::bind(LOCAL).expect("Listener failed to bind");
    server.set_nonblocking(true).expect("failed to initialize non-blocking");

    let mut clients: Vec<Client> = vec![];
    let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
    loop {
        if let Ok((socket, addr)) = server.accept() {
            println!("Client {} connected", addr);

            let tx = tx.clone();
            let mut client_socket = socket.try_clone().expect("Failed to clone client socket");

            clients.push(Client {
                socket,
                connected_at: SystemTime::now(),
            });

            thread::spawn(move || {
                loop {
                    let mut buff = vec![0; MSG_SIZE];

                    match client_socket.read_exact(&mut buff) {
                        Ok(_) => {
                            let total_len = u32::from_le_bytes(
                                buff[0..4].try_into().unwrap()
                            ) as usize;
                            if total_len > MSG_SIZE {
                                let mut rest = vec![0; total_len - MSG_SIZE];
                                match client_socket.read_exact(&mut rest) {
                                    Ok(_) => {
                                        buff.extend(rest);
                                    }
                                    Err(e) => {
                                        println!("failed to read rest of message: {:?}", e);
                                        break;
                                    }
                                }
                            }
                            let msg = Message {
                                data: buff.clone(),
                                timestamp: SystemTime::now(),
                            };

                            let subsec_nanos = msg.timestamp
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .subsec_nanos();
                            let ms = subsec_nanos / 1_000_000;
                            let ns = subsec_nanos % 1_000_000;
                            let timestamp = msg.timestamp
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as i64;
                            let datetime = DateTime::<Utc>::from_timestamp(timestamp, 0).unwrap();
                            let full_msg_hex = buff.iter().map(|b| format!("{:02X}", b)).collect::<String>()[..total_len * 2].to_string();
                            println!(
                                "{}: {}.{:03}.{:06} UTC transmitted {} bytes: {}",
                                addr,
                                datetime.format("%Y-%m-%d %H:%M:%S"),
                                ms,
                                ns,
                                total_len,
                                full_msg_hex
                            );
                            tx.send(msg.data).expect("failed to send msg to rx");
                        }
                        Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
                        Err(_) => {
                            println!("closing connection with: {}", addr);
                            break;
                        }
                    }
                    sleep();
                }
            });
        }

        if let Ok(msg) = rx.try_recv() {
            clients = clients
                .into_iter()
                .filter_map(|mut client| {
                    let mut buff = msg.clone();
                    let total_len = u32::from_le_bytes(buff[0..4].try_into().unwrap()) as usize;
                    let packet_len = std::cmp::max(total_len, MSG_SIZE);
                    buff.resize(packet_len, 0);

                    if client.connected_at <= SystemTime::now() {
                        client.socket
                            .write_all(&buff)
                            .map(|_| client)
                            .ok()
                    } else {
                        Some(client)
                    }
                })
                .collect::<Vec<_>>();
        }

        sleep();
    }
}
