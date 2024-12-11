use aes::cipher::{BlockSizeUser, KeySizeUser};
use aes::Aes256;
use block_padding::Pkcs7;
use cbc;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use clear_on_drop::clear::Clear;
use generic_array::{typenum::U32, GenericArray};
use hkdf::Hkdf;
use hmac::digest::OutputSizeUser;
use hmac::{Hmac, Mac};
use ksi_double_ratchet::{self as dr, KeyPair as _};
use rand_core::{CryptoRng, RngCore};
use rand_os::OsRng;
use sha2::Sha256;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;
use x25519_dalek::{self, SharedSecret};

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 64;

pub type SignalDR = dr::DoubleRatchet<SignalCryptoProvider>;

pub struct SignalCryptoProvider;

impl dr::CryptoProvider for SignalCryptoProvider {
    type PublicKey = PublicKey;
    type KeyPair = KeyPair;
    type SharedSecret = SharedSecret;

    type RootKey = SymmetricKey;
    type ChainKey = SymmetricKey;
    type MessageKey = SymmetricKey;

    fn diffie_hellman(us: &KeyPair, them: &PublicKey) -> SharedSecret {
        us.private.diffie_hellman(&them.0)
    }

    fn kdf_rk(rk: &SymmetricKey, s: &SharedSecret) -> (SymmetricKey, SymmetricKey) {
        let salt: Option<&[u8]> = Some(rk.0.as_slice());
        let input_key_material: &[u8; 32] = s.as_bytes();
        let pseudo_random_key = Hkdf::<Sha256>::new(salt, input_key_material);

        let info = &b"WhisperRatchet"[..];
        let mut output_key_material = [0; 64];
        pseudo_random_key
            .expand(&info, &mut output_key_material)
            .unwrap();

        let root_key: GenericArray<u8, _> =
            GenericArray::<u8, U32>::from_slice(&output_key_material[..32]).clone();

        let chain_key: GenericArray<u8, _> =
            GenericArray::<u8, U32>::from_slice(&output_key_material[32..]).clone();

        return (SymmetricKey(root_key), SymmetricKey(chain_key));
    }

    fn kdf_ck(ck: &SymmetricKey) -> (SymmetricKey, SymmetricKey) {
        let key = ck.0.as_slice();

        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(&[0x01]);
        let message_key = mac.finalize().into_bytes();

        // TODO: check if this is correct, maybe we should not recreate the mac and just somehow clear it
        //      - Kseen715, 2024.11.29
        mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(&[0x02]);
        let chain_key = mac.finalize().into_bytes();

        return (SymmetricKey(chain_key), SymmetricKey(message_key));
    }

    fn encrypt(key: &SymmetricKey, pt: &[u8], ad: &[u8]) -> Vec<u8> {
        let input_key_material = key.0.as_slice();
        let pseudo_random_key = Hkdf::<Sha256>::new(None, input_key_material);

        let info = b"WhisperMessageKeys";
        let mut output_key_material = [0; 80];
        pseudo_random_key
            .expand(info, &mut output_key_material)
            .unwrap();

        let encryption_key = GenericArray::<u8, <Aes256 as KeySizeUser>::KeySize>::from_slice(
            &output_key_material[..32],
        );
        let message_key =
            GenericArray::<u8, <Hmac<Sha256> as OutputSizeUser>::OutputSize>::from_slice(
                &output_key_material[32..64],
            );
        let iv = GenericArray::<u8, <Aes256 as BlockSizeUser>::BlockSize>::from_slice(
            &output_key_material[64..],
        );

        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        let ciphr = Aes256CbcEnc::new(encryption_key, iv);

        let mut mod_plaintext = pt.to_vec();
        let plaintext_len = pt.len();

        mod_plaintext.resize(plaintext_len + 16 - (plaintext_len % 16), 0);

        let ciphertext = match ciphr.encrypt_padded_mut::<Pkcs7>(&mut mod_plaintext, plaintext_len)
        {
            Ok(encrypted) => encrypted,
            Err(e) => panic!("Error: {:?}", e),
        };

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(message_key).unwrap();

        mac.update(ad);
        mac.update(&ciphertext);

        let tag = mac.finalize().into_bytes();
        let mut ciphertext_vec = ciphertext.to_vec();

        ciphertext_vec.extend((&tag[..8]).into_iter());

        output_key_material.clear();

        // println!("ct: {:?}", ciphertext_vec);

        ciphertext_vec
    }

    fn decrypt(key: &SymmetricKey, ct: &[u8], ad: &[u8]) -> Result<Vec<u8>, dr::DecryptError> {
        let input_key_material = key.0.as_slice();
        let pseudo_random_key = Hkdf::<Sha256>::new(None, input_key_material);
        let info = b"WhisperMessageKeys";
        let mut output_key_material = [0; 80];
        match pseudo_random_key.expand(info, &mut output_key_material) {
            Ok(_) => (),
            Err(e) => panic!("Error: {:?}", e),
        };
        let decryption_key = GenericArray::<u8, <Aes256 as KeySizeUser>::KeySize>::from_slice(
            &output_key_material[..32],
        );
        let message_key =
            GenericArray::<u8, <Hmac<Sha256> as OutputSizeUser>::OutputSize>::from_slice(
                &output_key_material[32..64],
            );
        let iv = GenericArray::<u8, <Aes256 as BlockSizeUser>::BlockSize>::from_slice(
            &output_key_material[64..],
        );

        let ciphertext_len = ct.len() - 8;

        let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(message_key) {
            Ok(mac) => mac,
            Err(e) => panic!("Error: {:?}", e),
        };

        mac.update(ad);
        mac.update(&ct[..ciphertext_len]);

        let tag = mac.finalize().into_bytes();

        if bool::from(!((&tag[..8]) == (&ct[ciphertext_len..]))) {
            output_key_material.clear();
            println!("Error: {:?}", dr::DecryptError::DecryptFailure);
            return Err(dr::DecryptError::DecryptFailure);
        }

        type Aes256CbcDec = cbc::Decryptor<Aes256>;
        let ciphr = Aes256CbcDec::new(decryption_key, iv);

        let mut ciphertext_vec = ct[..ciphertext_len].to_vec();

        return match ciphr.decrypt_padded_mut::<Pkcs7>(&mut ciphertext_vec) {
            Ok(pt) => {
                output_key_material.clear();
                // println!("pt: {:?}", pt);
                Ok(pt.to_vec())
            }
            Err(e) => {
                output_key_material.clear();
                println!("Error: {:?}", e);
                Err(dr::DecryptError::DecryptFailure)
            }
        };
    }
}

#[derive(Clone, Debug)]
pub struct PublicKey(x25519_dalek::PublicKey);

impl Eq for PublicKey {}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.0.as_bytes() == other.0.as_bytes()
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

impl<'a> From<&'a x25519_dalek::StaticSecret> for PublicKey {
    fn from(private: &'a x25519_dalek::StaticSecret) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(private))
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

pub struct KeyPair {
    private: x25519_dalek::StaticSecret,
    public: PublicKey,
}

impl fmt::Debug for KeyPair {
    #[cfg(debug_assertions)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KeyPair {{ private (bytes): {:?}, public: {:?} }}",
            self.private.to_bytes(),
            self.public
        )
    }

    #[cfg(not(debug_assertions))]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KeyPair {{ private (bytes): <hidden bytes>, public: {:?} }}",
            self.public
        )
    }
}

impl dr::KeyPair for KeyPair {
    type PublicKey = PublicKey;

    fn new<R: CryptoRng + RngCore>(rng: &mut R) -> KeyPair {
        let private = x25519_dalek::StaticSecret::new(rng);
        let public = PublicKey::from(&private);
        KeyPair { private, public }
    }

    fn public(&self) -> &PublicKey {
        &self.public
    }
}

#[derive(Default)]
pub struct SymmetricKey(GenericArray<u8, U32>);

impl fmt::Debug for SymmetricKey {
    #[cfg(debug_assertions)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SymmetricKey({:?})", self.0)
    }

    #[cfg(not(debug_assertions))]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SymmetricKey(<hidden bytes>)")
    }
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.0.clear();
    }
}

// MSG arch:
// - 1024u8:
//      - 4u8: total_len
//      - 4u8: meta_len
//          - 4u8: session_auth_data_len
//              - session_auth_data
//      - msg
fn main() {
    let shared_key: SymmetricKey = SymmetricKey(GenericArray::<u8, U32>::clone_from_slice(
        b"Output of a X3DH key exchange...",
    ));

    let mut client = TcpStream::connect(LOCAL).expect("Stream failed to connect");
    client
        .set_nonblocking(true)
        .expect("failed to initiate non-blocking");

    let (tx, rx) = mpsc::channel::<String>();

    thread::spawn(move || loop {
        let mut buff = vec![0; MSG_SIZE];
        match client.read_exact(&mut buff) {
            Ok(_) => {
                let my_session_auth_data = format!(
                    "{}:{}",
                    client.local_addr().unwrap().ip().to_string(),
                    client.local_addr().unwrap().port().to_string()
                ); 

                let total_len = u32::from_le_bytes(buff[0..4].try_into().unwrap()) as usize;

                buff = if total_len > MSG_SIZE {
                    // Read remaining data
                    let remaining = total_len - MSG_SIZE;
                    let mut remaining_buff = vec![0; remaining];
                    client.read_exact(&mut remaining_buff);
                    
                    // Combine buffers
                    let mut full_buff = buff;
                    full_buff.extend(remaining_buff);
                    full_buff
                } else {
                    buff
                };
                
                let meta_len = u32::from_le_bytes(buff[4..8].try_into().unwrap()) as usize;
                let meta = &buff[8..8 + meta_len];
                
                // println!("buf: {:?}", buff);
                // println!("total_len: {:?}", total_len);
                // println!("meta_len: {:?}", meta_len);
                
                let session_auth_data_len = u32::from_le_bytes(meta[0..4].to_vec().try_into().unwrap()) as usize;
                let session_auth_data = meta[4..session_auth_data_len + 4].to_vec();
                let mut session_auth_data_text = String::from_utf8(session_auth_data).expect("Invalid utf8 session_auth_data");
                if session_auth_data_text == my_session_auth_data {
                    session_auth_data_text = "-== YOU ==-".to_string();
                }

                let msg_text = buff[8 + meta_len..total_len].to_vec();
                let msg_text = String::from_utf8(msg_text).expect("Invalid utf8 message");
                
                // let msg_text_len = msg_text.len();
                // println!("msg_text_len: {:?}", msg_text_len);

                println!("{:?}: {:?}", session_auth_data_text, msg_text);
            }
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
            Err(_) => {
                println!("Connection with server was severed");
                break;
            }
        }

        match rx.try_recv() {
            Ok(msg) => {
                let mut buff: Vec<u8> = vec![];
                let msg_text_len = msg.len();
                
                let session_auth_data = format!(
                    "{}:{}",
                    client.local_addr().unwrap().ip().to_string(),
                    client.local_addr().unwrap().port().to_string()
                ); 
                let session_auth_data_len: u32 = session_auth_data.len() as u32;
                // println!("session_auth_data: {:?}", session_auth_data);
                
                let meta_len: u32 = 0 
                    + 4 // session_auth_data_len
                    + session_auth_data_len;

                let total_len: u32 = 0
                    + 4 // total_len
                    + 4 // meta_len
                    + meta_len 
                    + msg_text_len
                    as u32;

                buff.extend_from_slice(&total_len.to_le_bytes());
                buff.extend_from_slice(&meta_len.to_le_bytes());
                
                // meta:
                buff.extend_from_slice(&session_auth_data_len.to_le_bytes());
                buff.append(&mut session_auth_data.clone().into_bytes());
                
                // msg_text:
                buff.append(&mut msg.clone().into_bytes());

                let packet_len = std::cmp::max(MSG_SIZE, buff.len());
                buff.resize(packet_len, 0);
                client.write_all(&buff).expect("Writing to socket failed");
                // println!("Message sent {:?}", msg);
                // println!("Buff sent {:?}", buff);
            }
            Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => break,
        }

        thread::sleep(Duration::from_millis(100));
    });

    println!("Write a Message:");
    loop {
        let mut buff = String::new();
        io::stdin()
            .read_line(&mut buff)
            .expect("Reading from stdin failed");
        let msg = buff.trim().to_string();
        if msg == ":quit" || tx.send(msg).is_err() {
            break;
        }
    }
    println!("bye bye!");
}

// To run this program you need to open 2 terminals. One for the client and one for the server.
// In the server run `cargo run`.
// Then do the same in your client. And this time you should see a message, `write a message`.
// Type something and then you should see that in the server.
// If you type ':quit' then the program will quit...
