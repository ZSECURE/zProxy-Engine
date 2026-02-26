/// NTLM authentication helpers.
///
/// Implements the three-message NTLM handshake used by HTTP/HTTPS proxies:
///   Type 1 – Negotiate
///   Type 2 – Challenge  (server → client)
///   Type 3 – Authenticate (client → server)
///
/// The NT response uses the NTLMv1 "NT response" scheme (NTHash + three
/// independent single-block DES ECB encryptions of the 8-byte server challenge).
/// This is intentionally kept simple; real deployments should use NTLMv2.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};

// ---------------------------------------------------------------------------
// NTLM flag bits (subset)
// ---------------------------------------------------------------------------
pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
pub const NEGOTIATE_OEM: u32 = 0x0000_0002;
pub const REQUEST_TARGET: u32 = 0x0000_0004;
pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
pub const NEGOTIATE_WORKSTATION_SUPPLIED: u32 = 0x0000_2000;
pub const NEGOTIATE_DOMAIN_SUPPLIED: u32 = 0x0000_1000;

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

// ---------------------------------------------------------------------------
// Type 1 – Negotiate
// ---------------------------------------------------------------------------

/// Build an NTLM Type 1 (Negotiate) message.
pub fn create_negotiate_message() -> Vec<u8> {
    let flags: u32 = NEGOTIATE_UNICODE
        | NEGOTIATE_OEM
        | REQUEST_TARGET
        | NEGOTIATE_NTLM
        | NEGOTIATE_ALWAYS_SIGN;

    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(NTLMSSP_SIGNATURE); // 8 bytes
    msg.extend_from_slice(&1u32.to_le_bytes()); // MessageType = 1
    msg.extend_from_slice(&flags.to_le_bytes()); // NegotiateFlags
    // DomainNameFields  (length=0, maxlength=0, offset=32)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&32u32.to_le_bytes());
    // WorkstationFields (length=0, maxlength=0, offset=32)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&32u32.to_le_bytes());
    msg
}

/// Return the `Proxy-Authorization` header value for the negotiate step.
pub fn create_negotiate_header() -> String {
    format!("NTLM {}", STANDARD.encode(create_negotiate_message()))
}

// ---------------------------------------------------------------------------
// Type 2 – Challenge (parse server message)
// ---------------------------------------------------------------------------

pub struct NtlmChallenge {
    pub server_challenge: [u8; 8],
    pub flags: u32,
    pub target_name: String,
}

/// Parse an NTLM Type 2 (Challenge) message.
pub fn parse_challenge(data: &[u8]) -> Result<NtlmChallenge> {
    if data.len() < 32 {
        return Err(anyhow!("NTLM challenge too short: {} bytes", data.len()));
    }
    if &data[0..8] != NTLMSSP_SIGNATURE {
        return Err(anyhow!("Invalid NTLM signature"));
    }
    let msg_type = u32::from_le_bytes(data[8..12].try_into()?);
    if msg_type != 2 {
        return Err(anyhow!("Expected NTLM Type 2, got {}", msg_type));
    }

    let flags = u32::from_le_bytes(data[20..24].try_into()?);

    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&data[24..32]);

    // Target name is optional; parse from the security buffer at offset 12..20
    let target_name = if data.len() >= 20 {
        let target_len = u16::from_le_bytes(data[12..14].try_into()?) as usize;
        let target_offset = u32::from_le_bytes(data[16..20].try_into()?) as usize;
        if target_offset + target_len <= data.len() && target_len > 0 {
            let raw = &data[target_offset..target_offset + target_len];
            // May be UTF-16LE
            if flags & NEGOTIATE_UNICODE != 0 {
                let utf16: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                String::from_utf16_lossy(&utf16).to_string()
            } else {
                String::from_utf8_lossy(raw).to_string()
            }
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    Ok(NtlmChallenge { server_challenge: challenge, flags, target_name })
}

// ---------------------------------------------------------------------------
// Type 3 – Authenticate
// ---------------------------------------------------------------------------

/// Build an NTLM Type 3 (Authenticate) message using NTLMv1.
pub fn create_authenticate_message(
    challenge: &NtlmChallenge,
    username: &str,
    password: &str,
    domain: &str,
) -> Vec<u8> {
    let nt_response = compute_nt_response(password, &challenge.server_challenge);
    let lm_response = vec![0u8; 24]; // empty LM response

    let domain_utf16 = to_utf16le(domain);
    let username_utf16 = to_utf16le(username);
    let workstation_utf16 = to_utf16le("WORKSTATION");

    // Fixed header size: 72 bytes
    let base_offset = 72usize;
    let lm_offset = base_offset as u32;
    let nt_offset = lm_offset + lm_response.len() as u32;
    let domain_offset = nt_offset + nt_response.len() as u32;
    let username_offset = domain_offset + domain_utf16.len() as u32;
    let workstation_offset = username_offset + username_utf16.len() as u32;

    let flags: u32 = NEGOTIATE_UNICODE | NEGOTIATE_NTLM | NEGOTIATE_ALWAYS_SIGN;

    let mut msg = Vec::with_capacity(base_offset + 24 + 24 + domain_utf16.len() + username_utf16.len() + workstation_utf16.len());

    msg.extend_from_slice(NTLMSSP_SIGNATURE);
    msg.extend_from_slice(&3u32.to_le_bytes()); // MessageType

    // LmChallengeResponseFields
    write_security_buffer(&mut msg, lm_response.len() as u16, lm_offset);
    // NtChallengeResponseFields
    write_security_buffer(&mut msg, nt_response.len() as u16, nt_offset);
    // DomainNameFields
    write_security_buffer(&mut msg, domain_utf16.len() as u16, domain_offset);
    // UserNameFields
    write_security_buffer(&mut msg, username_utf16.len() as u16, username_offset);
    // WorkstationFields
    write_security_buffer(&mut msg, workstation_utf16.len() as u16, workstation_offset);
    // EncryptedRandomSessionKeyFields (empty)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&(workstation_offset + workstation_utf16.len() as u32).to_le_bytes());
    // NegotiateFlags
    msg.extend_from_slice(&flags.to_le_bytes());

    // Payload
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&nt_response);
    msg.extend_from_slice(&domain_utf16);
    msg.extend_from_slice(&username_utf16);
    msg.extend_from_slice(&workstation_utf16);

    msg
}

/// Build the `Proxy-Authorization` header value for the authenticate step.
pub fn create_authenticate_header(
    challenge_data: &[u8],
    username: &str,
    password: &str,
    domain: &str,
) -> Result<String> {
    let challenge = parse_challenge(challenge_data)?;
    let msg = create_authenticate_message(&challenge, username, password, domain);
    Ok(format!("NTLM {}", STANDARD.encode(&msg)))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the 24-byte NTLMv1 NT response.
fn compute_nt_response(password: &str, server_challenge: &[u8; 8]) -> Vec<u8> {
    // NT hash = MD4(UTF-16LE(password))
    let nt_hash = md4(to_utf16le(password).as_slice());

    // Pad to 21 bytes, split into three 7-byte keys, DES-encrypt the challenge
    let mut padded = [0u8; 21];
    padded[..16].copy_from_slice(&nt_hash);

    let mut response = Vec::with_capacity(24);
    for i in 0..3 {
        let key7 = &padded[i * 7..(i + 1) * 7];
        let des_key = expand_des_key(key7);
        response.extend_from_slice(&des_ecb_encrypt(&des_key, server_challenge));
    }
    response
}

/// Minimal MD4 implementation (RFC 1320).
fn md4(input: &[u8]) -> [u8; 16] {
    // Use hmac/md-5 crate isn't available for md4; implement from scratch.
    let mut a: u32 = 0x6745_2301;
    let mut b: u32 = 0xEFCD_AB89;
    let mut c: u32 = 0x98BA_DCFE;
    let mut d: u32 = 0x1032_5476;

    // Prepare message
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, w) in x.iter_mut().enumerate() {
            *w = u32::from_le_bytes(chunk[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        let (aa, bb, cc, dd) = (a, b, c, d);

        macro_rules! f { ($x:expr,$y:expr,$z:expr) => { ($x & $y) | (!$x & $z) }; }
        macro_rules! g { ($x:expr,$y:expr,$z:expr) => { ($x & $y) | ($x & $z) | ($y & $z) }; }
        macro_rules! h { ($x:expr,$y:expr,$z:expr) => { $x ^ $y ^ $z }; }
        macro_rules! rot { ($v:expr,$s:expr) => { $v.rotate_left($s) }; }

        // Round 1
        for &(i, s) in &[(0,3),(1,7),(2,11),(3,19),(4,3),(5,7),(6,11),(7,19),(8,3),(9,7),(10,11),(11,19),(12,3),(13,7),(14,11),(15,19u32)] {
            a = rot!(a.wrapping_add(f!(b,c,d)).wrapping_add(x[i]), s);
            let tmp = d; d = c; c = b; b = a; a = tmp;
        }
        // Round 2
        for &(i, s) in &[(0,3),(4,5),(8,9),(12,13),(1,3),(5,5),(9,9),(13,13),(2,3),(6,5),(10,9),(14,13),(3,3),(7,5),(11,9),(15,13u32)] {
            a = rot!(a.wrapping_add(g!(b,c,d)).wrapping_add(x[i]).wrapping_add(0x5A82_7999), s);
            let tmp = d; d = c; c = b; b = a; a = tmp;
        }
        // Round 3
        for &(i, s) in &[(0,3),(8,9),(4,11),(12,15),(2,3),(10,9),(6,11),(14,15),(1,3),(9,9),(5,11),(13,15),(3,3),(11,9),(7,11),(15,15u32)] {
            a = rot!(a.wrapping_add(h!(b,c,d)).wrapping_add(x[i]).wrapping_add(0x6ED9_EBA1), s);
            let tmp = d; d = c; c = b; b = a; a = tmp;
        }

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes());
    out[12..16].copy_from_slice(&d.to_le_bytes());
    out
}

/// Expand a 7-byte key into an 8-byte DES key with odd parity.
fn expand_des_key(key7: &[u8]) -> [u8; 8] {
    let mut key8 = [0u8; 8];
    key8[0] = key7[0] >> 1;
    key8[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2);
    key8[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3);
    key8[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4);
    key8[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5);
    key8[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6);
    key8[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7);
    key8[7] = key7[6] & 0x7F;
    for b in &mut key8 {
        // Shift so the 7 key bits occupy bits 7–1; bit 0 is the parity bit.
        *b <<= 1;
        // Adjust bit 0 to ensure odd parity (XOR of all bits == 1).
        if b.count_ones() % 2 == 0 {
            *b ^= 0x01;
        }
    }
    key8
}

/// Single-block DES ECB encryption (8-byte block).
fn des_ecb_encrypt(key: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    // DES IP permutation table
    const IP: [u8; 64] = [
        58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
        57,49,41,33,25,17, 9,1, 59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7,
    ];
    const IP_INV: [u8; 64] = [
        40, 8,48,16,56,24,64,32, 39, 7,47,15,55,23,63,31,
        38, 6,46,14,54,22,62,30, 37, 5,45,13,53,21,61,29,
        36, 4,44,12,52,20,60,28, 35, 3,43,11,51,19,59,27,
        34, 2,42,10,50,18,58,26, 33, 1,41, 9,49,17,57,25,
    ];
    const E: [u8; 48] = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9,10,11,
        12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,
        22,23,24,25,24,25,26,27,28,29,28,29,30,31,32, 1,
    ];
    const P: [u8; 32] = [
        16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
         2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25,
    ];
    const PC1_C: [u8; 28] = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36];
    const PC1_D: [u8; 28] = [63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4];
    const PC2: [u8; 48] = [
        14,17,11,24, 1, 5, 3,28,15, 6,21,10,23,19,12, 4,
        26, 8,16, 7,27,20,13, 2,41,52,31,37,47,55,30,40,
        51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32,
    ];
    const S: [[u8; 64]; 8] = [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
    ];
    const SHIFTS: [u8; 16] = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];

    fn get_bit(data: &[u8], pos: usize) -> u8 {
        let byte = pos / 8;
        let bit = 7 - (pos % 8);
        (data[byte] >> bit) & 1
    }
    fn set_bit(data: &mut [u8], pos: usize, val: u8) {
        let byte = pos / 8;
        let bit = 7 - (pos % 8);
        if val == 1 {
            data[byte] |= 1 << bit;
        } else {
            data[byte] &= !(1 << bit);
        }
    }

    // Generate subkeys
    let mut c = [0u8; 4]; // 28 bits
    let mut d = [0u8; 4]; // 28 bits
    for (i, &p) in PC1_C.iter().enumerate() {
        let b = get_bit(key, (p - 1) as usize);
        set_bit(&mut c, i, b);
    }
    for (i, &p) in PC1_D.iter().enumerate() {
        let b = get_bit(key, (p - 1) as usize);
        set_bit(&mut d, i, b);
    }

    let mut cv = 0u32;
    let mut dv = 0u32;
    for i in 0..28 {
        cv |= (get_bit(&c, i) as u32) << (27 - i);
        dv |= (get_bit(&d, i) as u32) << (27 - i);
    }

    let mut subkeys = [[0u8; 6]; 16];
    for round in 0..16 {
        let shift = SHIFTS[round] as u32;
        cv = ((cv << shift) | (cv >> (28 - shift))) & 0x0FFF_FFFF;
        dv = ((dv << shift) | (dv >> (28 - shift))) & 0x0FFF_FFFF;

        let mut cd = [0u8; 7]; // 56 bits combined
        for i in 0..28 {
            let cb = ((cv >> (27 - i)) & 1) as u8;
            let db = ((dv >> (27 - i)) & 1) as u8;
            set_bit(&mut cd, i, cb);
            set_bit(&mut cd, 28 + i, db);
        }
        for (i, &p) in PC2.iter().enumerate() {
            let b = get_bit(&cd, (p - 1) as usize);
            set_bit(&mut subkeys[round], i, b);
        }
    }

    // IP permutation
    let mut l = [0u8; 4];
    let mut r = [0u8; 4];
    for (i, &p) in IP.iter().enumerate() {
        let b = get_bit(block, (p - 1) as usize);
        if i < 32 {
            set_bit(&mut l, i, b);
        } else {
            set_bit(&mut r, i - 32, b);
        }
    }

    // 16 Feistel rounds
    for round in 0..16 {
        let subkey = &subkeys[round];

        // Expansion E
        let mut er = [0u8; 6];
        for (i, &p) in E.iter().enumerate() {
            let b = get_bit(&r, (p - 1) as usize);
            set_bit(&mut er, i, b);
        }

        // XOR with subkey
        for i in 0..6 {
            er[i] ^= subkey[i];
        }

        // S-boxes
        let mut sr = [0u8; 4];
        for s in 0..8 {
            let b0 = get_bit(&er, s * 6) as usize;
            let b5 = get_bit(&er, s * 6 + 5) as usize;
            let row = (b0 << 1) | b5;
            let col = ((get_bit(&er, s * 6 + 1) as usize) << 3)
                | ((get_bit(&er, s * 6 + 2) as usize) << 2)
                | ((get_bit(&er, s * 6 + 3) as usize) << 1)
                | (get_bit(&er, s * 6 + 4) as usize);
            let val = S[s][row * 16 + col];
            for b in 0..4 {
                set_bit(&mut sr, s * 4 + b, (val >> (3 - b)) & 1);
            }
        }

        // P permutation
        let mut pr = [0u8; 4];
        for (i, &p) in P.iter().enumerate() {
            let b = get_bit(&sr, (p - 1) as usize);
            set_bit(&mut pr, i, b);
        }

        // L XOR f(R)
        let new_r = [l[0] ^ pr[0], l[1] ^ pr[1], l[2] ^ pr[2], l[3] ^ pr[3]];
        l = r;
        r = new_r;
    }

    // Combine R, L (swapped)
    let mut rl = [0u8; 8];
    for i in 0..32 {
        set_bit(&mut rl, i, get_bit(&r, i));
        set_bit(&mut rl, 32 + i, get_bit(&l, i));
    }

    // Inverse IP
    let mut out = [0u8; 8];
    for (i, &p) in IP_INV.iter().enumerate() {
        let b = get_bit(&rl, (p - 1) as usize);
        set_bit(&mut out, i, b);
    }
    out
}

fn to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

fn write_security_buffer(buf: &mut Vec<u8>, length: u16, offset: u32) {
    buf.extend_from_slice(&length.to_le_bytes());
    buf.extend_from_slice(&length.to_le_bytes()); // MaxLength == Length
    buf.extend_from_slice(&offset.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiate_message_signature() {
        let msg = create_negotiate_message();
        assert_eq!(&msg[0..8], b"NTLMSSP\0");
        assert_eq!(&msg[8..12], &1u32.to_le_bytes()); // Type 1
    }

    #[test]
    fn test_negotiate_header() {
        let hdr = create_negotiate_header();
        assert!(hdr.starts_with("NTLM "));
        // Decode and verify
        let b64 = hdr.strip_prefix("NTLM ").unwrap();
        let data = STANDARD.decode(b64).unwrap();
        assert_eq!(&data[0..8], b"NTLMSSP\0");
    }

    #[test]
    fn test_md4_empty() {
        // MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
        let digest = md4(b"");
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn test_des_key_expansion() {
        let key7 = [0u8; 7];
        let key8 = expand_des_key(&key7);
        // All-zero 7-byte key: after expanding and setting odd parity,
        // each byte has count_ones() == 0 (even), so parity bit is set to 1.
        assert!(key8.iter().all(|&b| b == 0x01));
    }
}
