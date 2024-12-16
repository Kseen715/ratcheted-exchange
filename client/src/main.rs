use aes::cipher::{ BlockSizeUser, KeySizeUser };
use aes::Aes256;
use block_padding::Pkcs7;
use cbc;
use cipher::{ BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit };
use clear_on_drop::clear::Clear;
use generic_array::{ typenum::U32, GenericArray };
use hkdf::Hkdf;
use hmac::digest::OutputSizeUser;
use hmac::{ Hmac, Mac };
use ksi_double_ratchet::{ self as dr, Header, KeyPair as _ };
use rand_core::{ CryptoRng, RngCore };
use rand_os::OsRng;
use sha2::Sha256;
use std::fmt;
use std::hash::{ Hash, Hasher };
use std::io::{ self, ErrorKind, Read, Write };
use std::net::TcpStream;
use std::sync::mpsc::{ self, TryRecvError };
use std::thread;
use std::time::Duration;
use x25519_dalek::{ self, SharedSecret };
use base64::prelude::*;

const SERVER: &str = "127.0.0.1:6000";
const BASE_MSG_SIZE: usize = 512;

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
        pseudo_random_key.expand(&info, &mut output_key_material).unwrap();

        let root_key: GenericArray<u8, _> = GenericArray::<u8, U32>
            ::from_slice(&output_key_material[..32])
            .clone();

        let chain_key: GenericArray<u8, _> = GenericArray::<u8, U32>
            ::from_slice(&output_key_material[32..])
            .clone();

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
        pseudo_random_key.expand(info, &mut output_key_material).unwrap();

        let encryption_key = GenericArray::<u8, <Aes256 as KeySizeUser>::KeySize>::from_slice(
            &output_key_material[..32]
        );
        let message_key = GenericArray::<
            u8,
            <Hmac<Sha256> as OutputSizeUser>::OutputSize
        >::from_slice(&output_key_material[32..64]);
        let iv = GenericArray::<u8, <Aes256 as BlockSizeUser>::BlockSize>::from_slice(
            &output_key_material[64..]
        );

        type Aes256CbcEnc = cbc::Encryptor<Aes256>;
        let ciphr = Aes256CbcEnc::new(encryption_key, iv);

        let mut mod_plaintext = pt.to_vec();
        let plaintext_len = pt.len();

        mod_plaintext.resize(plaintext_len + 16 - (plaintext_len % 16), 0);

        let ciphertext = match ciphr.encrypt_padded_mut::<Pkcs7>(&mut mod_plaintext, plaintext_len) {
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
        }
        let decryption_key = GenericArray::<u8, <Aes256 as KeySizeUser>::KeySize>::from_slice(
            &output_key_material[..32]
        );
        let message_key = GenericArray::<
            u8,
            <Hmac<Sha256> as OutputSizeUser>::OutputSize
        >::from_slice(&output_key_material[32..64]);
        let iv = GenericArray::<u8, <Aes256 as BlockSizeUser>::BlockSize>::from_slice(
            &output_key_material[64..]
        );

        let ciphertext_len = ct.len() - 8;

        let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(message_key) {
            Ok(mac) => mac,
            Err(e) => panic!("Error: {:?}", e),
        };

        mac.update(ad);
        mac.update(&ct[..ciphertext_len]);

        let tag = mac.finalize().into_bytes();

        if bool::from(!(&tag[..8] == &ct[ciphertext_len..])) {
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
        write!(f, "KeyPair {{ private (bytes): <hidden bytes>, public: {:?} }}", self.public)
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

impl Clone for SymmetricKey {
    fn clone(&self) -> SymmetricKey {
        SymmetricKey(self.0.clone())
    }
}

impl Clone for KeyPair {
    fn clone(&self) -> KeyPair {
        KeyPair {
            private: self.private.clone(),
            public: self.public.clone(),
        }
    }
}

impl AsRef<[u8]> for SymmetricKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

fn read_msg_from_buff(
    buff: &Vec<u8>,
    our_auth_data_b64: &String,
    bob_auth_data_b64: &String
) -> (String, String, String) {
    // println!("[dbg] Start read_msg_from_buff");
    let total_len = u32::from_le_bytes(buff[0..4].try_into().unwrap()) as usize;
    // println!("total_len: {:?}", total_len);

    // let my_session_auth_data = our_auth_data_b64.clone();

    let meta_len = u32::from_le_bytes(buff[4..8].try_into().unwrap()) as usize;
    let meta = &buff[8..8 + meta_len];
    // println!("meta_len: {:?}", meta_len);

    let sent_from_auth_data_len = u32::from_le_bytes(
        meta[0..4].to_vec().try_into().unwrap()
    ) as usize;
    // println!("[312] sent_from_auth_data_len: {:?}", sent_from_auth_data_len);
    let sent_from_auth_data = meta[4..sent_from_auth_data_len + 4].to_vec();
    let sent_from_auth_data = String::from_utf8(sent_from_auth_data).expect(
        "Invalid utf8 sent_from_auth_data"
    );

    let sent_to_auth_data_len = u32::from_le_bytes(
        meta[sent_from_auth_data_len + 4..sent_from_auth_data_len + 8].to_vec().try_into().unwrap()
    ) as usize;
    // println!("sent_to_auth_data_len: {:?}", sent_to_auth_data_len);

    let sent_to_auth_data =
        meta[
            sent_from_auth_data_len + 8..sent_from_auth_data_len + 8 + sent_to_auth_data_len
        ].to_vec();
    let sent_to_auth_data = String::from_utf8(sent_to_auth_data).expect(
        "Invalid utf8 sent_to_auth_data"
    );

    let header_len: usize = u32::from_le_bytes(
        meta[
            sent_from_auth_data_len + 8 + sent_to_auth_data_len..sent_from_auth_data_len +
                12 +
                sent_to_auth_data_len
        ]
            .to_vec()
            .try_into()
            .unwrap()
    ) as usize;
    // println!("header_len: {:?}", header_len);
    let header =
        meta[
            sent_from_auth_data_len + 12 + sent_to_auth_data_len..sent_from_auth_data_len +
                12 +
                sent_to_auth_data_len +
                header_len
        ].to_vec();
    // println!("header_b64: {:?}", header);
    let header = String::from_utf8(header).expect("Invalid utf8 header");
    // println!("header: {:?}", header);

    // println!("sent_from_auth_data_b64: {:?}", sent_from_auth_data);
    // println!("sent_to_auth_data_b64: {:?}", sent_to_auth_data);
    // println!("our_auth_data_b64: {:?}", our_auth_data_b64);
    // println!("bob_auth_data_b64: {:?}", bob_auth_data_b64);

    // println!("calc_size: {:?}", total_len - (8 + meta_len));
    let msg_text = buff[8 + meta_len..total_len].to_vec();
    let msg_text = String::from_utf8(msg_text).expect("Invalid utf8 message");
    // println!("msg_text_b64: {:?}", msg_text);

    if
        sent_to_auth_data != our_auth_data_b64.clone() ||
        sent_from_auth_data != bob_auth_data_b64.clone()
    {
        // drop the message if it's not from the person we're talking to
        // or if it's from ourselves
        // println!("[dbg] End read_msg_from_buff");
        return (String::from(""), String::from(""), String::from(""));
    }

    // println!("[dbg] End read_msg_from_buff");
    return (sent_from_auth_data, header, msg_text);
}

fn prepare_buff_to_send_msg(
    buff: &mut Vec<u8>,
    our_auth_data_b64: &String,
    bob_auth_data_b64: &String,
    header_b64: &String,
    msg_b64: &String
) {
    // println!("[dbg] Start prepare_buff_to_send_msg");
    let msg_b64_text_len = msg_b64.len();
    // println!("our_auth_data_b64: {:?}", our_auth_data_b64);
    // println!("bob_auth_data_b64: {:?}", bob_auth_data_b64);
    // println!("header_b64: {:?}", header_b64);
    // println!("msg_b64: {:?}", msg_b64);

    let session_auth_data = our_auth_data_b64.clone();
    let session_auth_data_len: u32 = session_auth_data.len() as u32;

    let bobs_auth_data = bob_auth_data_b64.clone();
    let bobs_auth_data_len: u32 = bobs_auth_data.len() as u32;

    let header_b64_len = header_b64.len() as u32;

    let meta_len: u32 =
        4 + // session_auth_data_len
        session_auth_data_len +
        4 + // bobs_auth_data_len
        bobs_auth_data_len +
        4 + // header_len
        (header_b64_len as u32);

    let total_len: u32 =
        4 + // total_len
        4 + // meta_len
        meta_len +
        (msg_b64_text_len as u32);

    // println!("total_len: {:?}", total_len);
    // println!("meta_len: {:?}", meta_len);
    // println!("session_auth_data_len: {:?}", session_auth_data_len);
    // println!("bobs_auth_data_len: {:?}", bobs_auth_data_len);
    // println!("header_b64_len: {:?}", header_b64_len);
    // println!("msg_b64_text_len: {:?}", msg_b64_text_len);

    buff.extend_from_slice(&total_len.to_le_bytes());
    buff.extend_from_slice(&meta_len.to_le_bytes());

    // meta:
    buff.extend_from_slice(&session_auth_data_len.to_le_bytes());
    buff.append(&mut session_auth_data.clone().into_bytes());
    buff.extend_from_slice(&bobs_auth_data_len.to_le_bytes());
    buff.append(&mut bobs_auth_data.clone().into_bytes());
    buff.extend_from_slice(&header_b64_len.to_le_bytes());
    buff.append(&mut header_b64.clone().into_bytes());

    // msg_b64_text:
    buff.append(&mut msg_b64.clone().into_bytes());

    let packet_len = std::cmp::max(BASE_MSG_SIZE, buff.len());
    buff.resize(packet_len, 0);
    // println!("[dbg] End prepare_buff_to_send_msg");
}

// MSG arch:
//      - 4u8: total_len
//      - 4u8: meta_len
//          - 4u8: session_auth_data_len
//              - session_auth_data
//          - 4u8: bobs_auth_data_len
//              - bobs_auth_data
//          - 4u8: header_len
//              - header
//      - msg
fn main() {
    let mut rng = OsRng::new().unwrap();
    let shared_key: SymmetricKey = SymmetricKey(
        GenericArray::<u8, U32>::clone_from_slice(b"Output of a X3DH key exchange...")
    );

    let mut client = TcpStream::connect(SERVER).expect("Stream failed to connect");
    client.set_nonblocking(true).expect("failed to initiate non-blocking");

    let (tx, rx) = mpsc::channel::<String>();

    fn read_input(prompt: &str) -> String {
        print!("{}", prompt);
        io::stdout().flush().expect("Failed to flush stdout");

        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read input");

        input.trim().to_string()
    }

    let mut session_created: bool = false;

    #[derive(Debug)]
    enum UserKind {
        Undefined,
        Alice,
        Bob,
    }

    impl PartialEq for UserKind {
        fn eq(&self, other: &UserKind) -> bool {
            match (self, other) {
                (UserKind::Undefined, UserKind::Undefined) => true,
                (UserKind::Alice, UserKind::Alice) => true,
                (UserKind::Bob, UserKind::Bob) => true,
                _ => false,
            }
        }
    }

    fn bytes_to_type<T>(bytes: &[u8]) -> Header<PublicKey> {
        let mut value = std::mem::MaybeUninit::uninit();
        // println!("bytes: {:?}", bytes);
        // println!("size of T: {:?}", std::mem::size_of::<T>());
        // println!("size of bytes: {:?}", bytes.len());
        unsafe {
            // bytes is raw bytes of the struct
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                value.as_mut_ptr() as *mut u8,
                std::mem::size_of::<T>()
            );
            // Some()
            value.assume_init()
        }
    }

    let mut user_kind: UserKind = UserKind::Undefined;

    let mut alice: SignalDR = SignalDR::new_alice(
        &shared_key,
        PublicKey(x25519_dalek::PublicKey::from([0; 32])),
        None,
        &mut rng
    );
    let mut bob: SignalDR = SignalDR::new_bob(shared_key, KeyPair::new(&mut rng), None);

    let our_auth_data: String = read_input("Input your auth data: ");
    let bob_auth_data: String = read_input("Input bob's auth data: ");

    // Copy some values (these are usually the outcome of an X3DH key exchange)
    let bobs_prekey = KeyPair::new(&mut rng);
    let bobs_public_prekey = bobs_prekey.public().clone();
    let shared = SymmetricKey(
        GenericArray::<u8, U32>::clone_from_slice(b"Output of a X3DH key exchange...")
    );

    let mut buff: Vec<u8> = vec![];

    // send hex encoded public key
    prepare_buff_to_send_msg(
        &mut buff,
        &BASE64_STANDARD.encode(&our_auth_data),
        &BASE64_STANDARD.encode(&bob_auth_data),
        &BASE64_STANDARD.encode(&String::from("")),
        &BASE64_STANDARD.encode(&bobs_public_prekey.0.as_bytes())
    );
    // prepare_buff_to_send_msg(&mut buff, &our_auth_data, &bob_auth_data, &String::from("sending init key to Alice......."));
    client.write_all(&buff).expect("Writing to socket failed");

    thread::spawn(move || {
        loop {
            let mut buff = vec![0; BASE_MSG_SIZE];
            // Read message
            match client.read_exact(&mut buff) {
                Ok(_) => {
                    // println!("Message received ===============================");
                    // Read full message
                    let total_len = u32::from_le_bytes(buff[0..4].try_into().unwrap()) as usize;
                    buff = if total_len > BASE_MSG_SIZE {
                        // Read remaining data
                        let remaining = total_len - BASE_MSG_SIZE;
                        let mut remaining_buff = vec![0; remaining];
                        let _ = client.read_exact(&mut remaining_buff);

                        // Combine buffers
                        let mut full_buff = buff;
                        full_buff.extend(remaining_buff);
                        full_buff
                    } else {
                        buff
                    };

                    let (sent_from_auth_data_b64, header_b64, data_b64) = read_msg_from_buff(
                        &buff,
                        &BASE64_STANDARD.encode(&our_auth_data),
                        &BASE64_STANDARD.encode(&bob_auth_data)
                    );

                    let sent_from_auth_data = BASE64_STANDARD.decode(
                        &sent_from_auth_data_b64
                    ).unwrap();
                    let header = BASE64_STANDARD.decode(&header_b64).unwrap();
                    let header_bytes = header.as_slice();

                    // fill random 0-bytes to the size of the struct to init
                    use ksi_double_ratchet::Header;
                    let mut header: Header<PublicKey> = bytes_to_type::<Header<PublicKey>>(
                        [0; 40].as_ref()
                    );
                    if header_bytes.len() > 0 {
                        header = bytes_to_type::<Header<PublicKey>>(header_bytes);
                    } else {
                    }

                    let data = BASE64_STANDARD.decode(&data_b64).unwrap();

                    if sent_from_auth_data == "".as_bytes() || data == "".as_bytes() {
                        continue;
                    }

                    if !session_created {
                        // if string msg_text starts with [⚙️], then we are Bob and session is created
                        // if data.starts_with("[⚙️]".as_bytes()) {
                        if header_bytes.len() > 0 {
                            bob = SignalDR::new_bob(shared.clone(), bobs_prekey.clone(), None);
                            user_kind = UserKind::Bob;

                            let _ = bob
                                .ratchet_decrypt(&header, &data, &bob_auth_data.as_bytes())
                                .unwrap();

                            print!("\r\x1b[K"); // Clear current line
                            println!(
                                "{:?}: {:?}",
                                String::from_utf8(sent_from_auth_data).unwrap(),
                                "[🤙] Session created, I am <Alice> now"
                            );
                            print!("> "); // Reprint prompt
                            io::stdout().flush().expect("Failed to flush stdout");

                            // send msg to alice with bob's public key

                            session_created = true;
                            continue;
                        }
                        let bob_public_key_bytes = &data.clone();
                        let bob_public_key = PublicKey(
                            x25519_dalek::PublicKey::from(
                                <[u8; 32]>::try_from(bob_public_key_bytes.as_slice()).unwrap()
                            )
                        );

                        // Alice fetches Bob's prekey bundle and completes her side of the X3DH handshake
                        alice = SignalDR::new_alice(
                            &shared.clone(),
                            bob_public_key,
                            None,
                            &mut rng
                        );
                        user_kind = UserKind::Alice;

                        print!("\r\x1b[K"); // Clear current line
                        println!(
                            "{:?}: {:?}",
                            String::from_utf8(sent_from_auth_data).unwrap(),
                            "[🤙] Session created, I am <Bob> now"
                        );
                        print!("> "); // Reprint prompt
                        io::stdout().flush().expect("Failed to flush stdout");

                        // send msg to bob with first encrypted message
                        let plain = "Hello Bob, this is Alice".as_bytes();

                        let (h, ct) = alice.ratchet_encrypt(
                            &plain,
                            &our_auth_data.as_bytes(),
                            &mut rng
                        );

                        let h_u8: &[u8] = unsafe {
                            std::slice::from_raw_parts(
                                &h as *const _ as *const u8,
                                std::mem::size_of_val(&h)
                            )
                        };
                        // println!("hALICE len: {:?}", h_u8.len());
                        let mut buff: Vec<u8> = vec![];
                        prepare_buff_to_send_msg(
                            &mut buff,
                            &BASE64_STANDARD.encode(&our_auth_data),
                            &BASE64_STANDARD.encode(&bob_auth_data),
                            &BASE64_STANDARD.encode(&h_u8),
                            &BASE64_STANDARD.encode(&ct)
                        );
                        client.write_all(&buff).expect("Writing to socket failed");

                        // prepare_buff_to_send_msg(
                        //     &mut buff,
                        //     &BASE64_STANDARD.encode(&our_auth_data),
                        //     &BASE64_STANDARD.encode(&bob_auth_data),
                        //     &BASE64_STANDARD.encode(&String::from("")),
                        //     &BASE64_STANDARD.encode(&String::from("[⚙️]"))
                        // );

                        session_created = true;
                        // println!("[dbg] session_created: {:?}", session_created);
                    } else {
                        // println!("[dbg] user_kind: {:?}", user_kind);
                        if user_kind == UserKind::Alice {
                            // println!("[dbg] Begin decrypting message A =====================");
                            let decrypted = alice
                                .ratchet_decrypt(&header, &data, &bob_auth_data.as_bytes())
                                .unwrap();
                            print!("\r\x1b[K"); // Clear current line
                            println!(
                                "{:?}: {:?}",
                                String::from_utf8(sent_from_auth_data).unwrap(),
                                String::from_utf8(decrypted).unwrap()
                            );
                            print!("> "); // Reprint prompt
                            io::stdout().flush().expect("Failed to flush stdout");
                            // println!("[dbg] End decrypting message A =====================");
                        } else if user_kind == UserKind::Bob {
                            // println!("[dbg] Begin decrypting message B =====================");
                            let decrypted = bob
                                .ratchet_decrypt(&header, &data, &bob_auth_data.as_bytes())
                                .unwrap();
                            print!("\r\x1b[K"); // Clear current line
                            println!(
                                "{:?}: {:?}",
                                String::from_utf8(sent_from_auth_data).unwrap(),
                                String::from_utf8(decrypted).unwrap()
                            );
                            print!("> "); // Reprint prompt
                            io::stdout().flush().expect("Failed to flush stdout");
                            // println!("[dbg] End decrypting message B =====================");
                        } else {
                            println!("NOT ALICE NOR BOB ====================");
                            print!("\r\x1b[K"); // Clear current line
                            println!("{:?}: {:?}", sent_from_auth_data, data);
                            print!("> "); // Reprint prompt
                            io::stdout().flush().expect("Failed to flush stdout");
                        }
                    }
                }
                Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
                Err(_) => {
                    println!("Connection with server was severed");
                    break;
                }
            }

            // Send message
            match rx.try_recv() {
                Ok(msg) => {
                    let mut buff: Vec<u8> = vec![];
                    // println!("[dbg] user_kind: {:?}", user_kind);
                    if user_kind == UserKind::Alice {
                        // encrypt message
                        // println!("[dbg] Begin encrypting message A =====================");
                        let (h, ct) = alice.ratchet_encrypt(
                            &msg.as_bytes(),
                            &our_auth_data.as_bytes(),
                            &mut rng
                        );
                        let h_u8: &[u8] = unsafe {
                            std::slice::from_raw_parts(
                                &h as *const _ as *const u8,
                                std::mem::size_of_val(&h)
                            )
                        };
                        // println!("hALICE len: {:?}", h_u8.len());
                        prepare_buff_to_send_msg(
                            &mut buff,
                            &BASE64_STANDARD.encode(&our_auth_data),
                            &BASE64_STANDARD.encode(&bob_auth_data),
                            &BASE64_STANDARD.encode(&h_u8),
                            &BASE64_STANDARD.encode(&ct)
                        );
                        client.write_all(&buff).expect("Writing to socket failed");
                        // println!("[dbg] End encrypting message A =====================");
                    } else if user_kind == UserKind::Bob {
                        // encrypt message
                        // println!("[dbg] Begin encrypting message B =====================");
                        let (h, ct) = bob.ratchet_encrypt(
                            &msg.as_bytes(),
                            &our_auth_data.as_bytes(),
                            &mut rng
                        );
                        let h_u8: &[u8] = unsafe {
                            std::slice::from_raw_parts(
                                &h as *const _ as *const u8,
                                std::mem::size_of_val(&h)
                            )
                        };
                        // println!("hBOB len: {:?}", h_u8.len());
                        prepare_buff_to_send_msg(
                            &mut buff,
                            &BASE64_STANDARD.encode(&our_auth_data),
                            &BASE64_STANDARD.encode(&bob_auth_data),
                            &BASE64_STANDARD.encode(&h_u8),
                            &BASE64_STANDARD.encode(&ct)
                        );
                        client.write_all(&buff).expect("Writing to socket failed");
                        // println!("[dbg] End encrypting message B =====================");
                    } else {
                        // println!("NOT ALICE NOR BOB ====================");
                        println!("[ERROR] SESSION IS NOT ESTABLISHED");
                        prepare_buff_to_send_msg(
                            &mut buff,
                            &BASE64_STANDARD.encode(&our_auth_data),
                            &BASE64_STANDARD.encode(&bob_auth_data),
                            &BASE64_STANDARD.encode(&String::from("")),
                            &BASE64_STANDARD.encode(&msg)
                        );
                        client.write_all(&buff).expect("Writing to socket failed");
                    }
                    // prepare_buff_to_send_msg(
                    //     &mut buff,
                    //     &our_auth_data,
                    //     &bob_auth_data,
                    //     &String::from(""),
                    //     &msg
                    // );
                    // client.write_all(&buff).expect("Writing to socket failed");
                    // println!("Message sent {:?}", msg);
                    // println!("Buff sent {:?}", buff);
                }
                Err(TryRecvError::Empty) => (),
                Err(TryRecvError::Disconnected) => {
                    break;
                }
            }

            thread::sleep(Duration::from_millis(100));
        }
    });

    println!("Write a Message:");
    loop {
        // let mut buff = String::new();
        // io::stdin()
        //     .read_line(&mut buff)
        //     .expect("Reading from stdin failed");
        let buff = read_input("> ");
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
