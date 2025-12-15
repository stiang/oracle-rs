//! Debug test to identify where connection hangs

use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use oracle_rs::Config;
use oracle_rs::messages::ConnectMessage;

#[tokio::test]
#[ignore = "requires Oracle database"]
async fn debug_tcp_connection() {
    println!("Attempting TCP connection to localhost:1521...");

    let result = timeout(Duration::from_secs(5), TcpStream::connect("localhost:1521")).await;

    match result {
        Ok(Ok(stream)) => {
            println!("TCP connection established successfully!");
            println!("Local addr: {:?}", stream.local_addr());
            println!("Peer addr: {:?}", stream.peer_addr());
        }
        Ok(Err(e)) => {
            println!("TCP connection failed: {:?}", e);
        }
        Err(_) => {
            println!("TCP connection timed out after 5 seconds");
        }
    }
}

#[tokio::test]
#[ignore = "requires Oracle database"]
async fn debug_oracle_connect_packet() {
    use oracle_rs::Config;

    println!("Building connection config...");
    let mut config = Config::new("localhost", 1521, "FREEPDB1", "system", "testpass");
    config.set_password("testpass");
    println!("Config built: host={}, port={}", config.host, config.port);

    println!("Building connect string...");
    let connect_string = config.build_connect_string();
    println!("Connect string: {}", connect_string);

    // Use the proper ConnectMessage to build the packet
    use oracle_rs::messages::ConnectMessage;
    let connect_msg = ConnectMessage::from_config(&config);
    let (packet, _continuation) = connect_msg.build_with_continuation().unwrap();
    let packet = packet.to_vec();

    println!("\nAttempting TCP connection...");
    let stream = match timeout(Duration::from_secs(5), TcpStream::connect("localhost:1521")).await {
        Ok(Ok(stream)) => {
            println!("TCP connected!");
            stream
        }
        Ok(Err(e)) => {
            println!("TCP failed: {:?}", e);
            return;
        }
        Err(_) => {
            println!("TCP timeout");
            return;
        }
    };

    stream.set_nodelay(true).ok();

    println!("\nCONNECT packet size: {} bytes", packet.len());
    println!("First 40 bytes: {:02x?}", &packet[..40.min(packet.len())]);
    println!("Offset 74 bytes: {:02x?}", &packet[74.min(packet.len())..90.min(packet.len())]);

    println!("\nSending CONNECT packet...");
    let mut stream = stream;
    match timeout(Duration::from_secs(5), stream.write_all(&packet)).await {
        Ok(Ok(_)) => println!("CONNECT packet sent!"),
        Ok(Err(e)) => {
            println!("Write failed: {:?}", e);
            return;
        }
        Err(_) => {
            println!("Write timeout");
            return;
        }
    }

    stream.flush().await.ok();

    println!("\nWaiting for response...");
    let mut header_buf = [0u8; 8];
    match timeout(Duration::from_secs(10), stream.read_exact(&mut header_buf)).await {
        Ok(Ok(_)) => {
            let packet_len = u16::from_be_bytes([header_buf[0], header_buf[1]]);
            let packet_type = header_buf[4];
            println!("Response received!");
            println!("Header: {:02x?}", header_buf);
            println!("Packet length: {}", packet_len);
            println!("Packet type: {} (1=Connect, 2=Accept, 4=Refuse, 5=Redirect, 6=Data)", packet_type);

            // Read rest of packet if any
            let remaining = (packet_len as usize).saturating_sub(8);
            if remaining > 0 {
                let mut payload = vec![0u8; remaining.min(1024)];
                match timeout(Duration::from_secs(5), stream.read_exact(&mut payload)).await {
                    Ok(Ok(_)) => {
                        println!("Payload ({} bytes): {:02x?}", payload.len(), &payload[..payload.len().min(100)]);
                        // If REFUSE, try to decode the error
                        if packet_type == 4 {
                            let error_data = String::from_utf8_lossy(&payload[4..]);
                            println!("Refuse message: {}", error_data);
                        }
                    }
                    _ => println!("Could not read full payload"),
                }
            }
        }
        Ok(Err(e)) => println!("Read error: {:?}", e),
        Err(_) => println!("Response timeout (10 seconds)"),
    }
}

#[tokio::test]
#[ignore = "requires Oracle database"]
async fn debug_full_handshake() {
    println!("=== Full Handshake Debug Test ===\n");

    let mut config = Config::new("localhost", 1521, "FREEPDB1", "system", "testpass");
    config.set_password("testpass");

    // Connect
    println!("Step 1: TCP Connect...");
    let mut stream = match timeout(Duration::from_secs(5), TcpStream::connect("localhost:1521")).await {
        Ok(Ok(s)) => { println!("  OK: TCP connected"); s }
        Ok(Err(e)) => { println!("  FAIL: {:?}", e); return; }
        Err(_) => { println!("  FAIL: timeout"); return; }
    };
    stream.set_nodelay(true).ok();

    // Send CONNECT
    println!("\nStep 2: Send CONNECT packet...");
    let connect_msg = ConnectMessage::from_config(&config);
    let (packet, _) = connect_msg.build_with_continuation().unwrap();
    match stream.write_all(&packet).await {
        Ok(_) => println!("  OK: CONNECT sent ({} bytes)", packet.len()),
        Err(e) => { println!("  FAIL: {:?}", e); return; }
    }
    stream.flush().await.ok();

    // Receive ACCEPT
    println!("\nStep 3: Receive ACCEPT...");
    let response = match read_packet(&mut stream).await {
        Ok(data) => {
            let ptype = data[4];
            println!("  OK: Received {} bytes, type={}", data.len(), ptype);
            if ptype == 2 {
                println!("  Type: ACCEPT");
                // Parse accept response
                if data.len() > 8 {
                    let protocol_version = u16::from_be_bytes([data[8], data[9]]);
                    println!("  Protocol version: {}", protocol_version);
                }
            } else if ptype == 4 {
                println!("  Type: REFUSE");
                if data.len() > 12 {
                    let error = String::from_utf8_lossy(&data[12..]);
                    println!("  Error: {}", error);
                }
                return;
            }
            data
        }
        Err(e) => { println!("  FAIL: {:?}", e); return; }
    };

    // After ACCEPT with protocol version >= 315, use large_sdu format
    let protocol_version = u16::from_be_bytes([response[8], response[9]]);
    let service_options = u16::from_be_bytes([response[10], response[11]]);
    let use_large_sdu = protocol_version >= 315;
    let supports_oob = (service_options & 0x0400) != 0; // CAN_RECV_ATTENTION
    println!("  Using large_sdu: {} (protocol version {})", use_large_sdu, protocol_version);
    println!("  Service options: 0x{:04x}, supports_oob: {}", service_options, supports_oob);

    // OOB check for protocol version >= 318 AND server supports OOB
    if protocol_version >= 318 && supports_oob {
        println!("\nStep 4: OOB Check (protocol version >= 318)...");

        // Send raw byte "!" (0x21)
        match stream.write_all(&[0x21]).await {
            Ok(_) => println!("  OK: OOB '!' sent"),
            Err(e) => { println!("  FAIL sending '!': {:?}", e); return; }
        }
        stream.flush().await.ok();

        // Send MARKER packet with Reset
        let marker_packet = build_marker_packet(use_large_sdu);
        println!("  Sending MARKER packet ({} bytes): {:02x?}", marker_packet.len(), &marker_packet[..marker_packet.len().min(20)]);
        match stream.write_all(&marker_packet).await {
            Ok(_) => println!("  OK: MARKER sent"),
            Err(e) => { println!("  FAIL sending MARKER: {:?}", e); return; }
        }
        stream.flush().await.ok();

        // Wait for OOB response (use large_sdu format)
        // Server responds with CONTROL packet (type 14) with control type 9 (resetOOB)
        println!("  Waiting for OOB response...");
        match read_packet_with_sdu(&mut stream, use_large_sdu).await {
            Ok(data) => {
                let ptype = data[4];
                println!("  OK: Received {} bytes, type={}", data.len(), ptype);
                if ptype == 12 {
                    println!("  Type: MARKER");
                } else if ptype == 14 {
                    println!("  Type: CONTROL (OOB reset ack)");
                    if data.len() > 9 {
                        let control_type = u16::from_be_bytes([data[8], data[9]]);
                        println!("  Control type: {} (9=resetOOB)", control_type);
                    }
                } else {
                    println!("  Type: Unknown (expected 12=MARKER or 14=CONTROL)");
                }
            }
            Err(e) => { println!("  FAIL: {:?}", e); return; }
        };
    }

    // Send Protocol Request (DATA packet with MessageType::Protocol)
    println!("\nStep 5: Send PROTOCOL request...");
    let protocol_req = build_protocol_request_large_sdu(use_large_sdu);
    println!("  Protocol request ({} bytes): {:02x?}", protocol_req.len(), &protocol_req[..40.min(protocol_req.len())]);
    match stream.write_all(&protocol_req).await {
        Ok(_) => println!("  OK: PROTOCOL sent"),
        Err(e) => { println!("  FAIL: {:?}", e); return; }
    }
    stream.flush().await.ok();

    // Receive Protocol Response (use large_sdu format)
    println!("\nStep 6: Receive PROTOCOL response...");
    let caps = match read_packet_with_sdu(&mut stream, use_large_sdu).await {
        Ok(data) => {
            let ptype = data[4];
            println!("  OK: Received {} bytes, type={}", data.len(), ptype);
            if ptype == 6 {
                println!("  Type: DATA");
                if data.len() > 10 {
                    let msg_type = data[10];
                    println!("  Message type: {} (1=Protocol, 3=Function, 8=Error)", msg_type);

                    // Parse to get properly updated capabilities
                    if msg_type == 1 {
                        parse_protocol_response(&data)
                    } else {
                        oracle_rs::Capabilities::new()
                    }
                } else {
                    oracle_rs::Capabilities::new()
                }
            } else {
                oracle_rs::Capabilities::new()
            }
        }
        Err(e) => { println!("  FAIL: {:?}", e); return; }
    };

    // Step 7: Send DATA TYPES request (using properly parsed capabilities)
    println!("\nStep 7: Send DATA TYPES request...");
    let data_types_req = build_data_types_request(use_large_sdu, &caps);
    println!("  Data types request ({} bytes)", data_types_req.len());
    println!("  First 40 bytes: {:02x?}", &data_types_req[..40.min(data_types_req.len())]);
    match stream.write_all(&data_types_req).await {
        Ok(_) => println!("  OK: DATA TYPES sent"),
        Err(e) => { println!("  FAIL: {:?}", e); return; }
    }
    stream.flush().await.ok();

    // Receive Data Types Response
    println!("\nStep 8: Receive DATA TYPES response...");
    let _response = match read_packet_with_sdu(&mut stream, use_large_sdu).await {
        Ok(data) => {
            let ptype = data[4];
            println!("  OK: Received {} bytes, type={}", data.len(), ptype);
            if ptype == 6 {
                println!("  Type: DATA");
                if data.len() > 10 {
                    let msg_type = data[10];
                    println!("  Message type: {} (2=DataTypes, 3=Function, 8=Error)", msg_type);
                }
            }
            data
        }
        Err(e) => { println!("  FAIL: {:?}", e); return; }
    };

    // Track sequence number (starts at 1, increments after each Function message)
    let mut seq_num: u8 = 1;

    // Step 9: Send AUTH phase one (using properly parsed capabilities)
    println!("\nStep 9: Send AUTH phase one request (seq={})...", seq_num);
    let auth_req = build_auth_phase_one(use_large_sdu, &caps, seq_num);
    seq_num = seq_num.wrapping_add(1);
    println!("  Auth phase one request ({} bytes)", auth_req.len());
    println!("  First 40 bytes: {:02x?}", &auth_req[..40.min(auth_req.len())]);
    println!("  Full hex dump:");
    for (i, chunk) in auth_req.chunks(16).enumerate() {
        print!("    {:04x}: ", i * 16);
        for b in chunk {
            print!("{:02x} ", b);
        }
        println!();
    }
    match stream.write_all(&auth_req).await {
        Ok(_) => println!("  OK: AUTH phase one sent"),
        Err(e) => { println!("  FAIL: {:?}", e); return; }
    }
    stream.flush().await.ok();

    // Receive Auth phase one Response
    println!("\nStep 10: Receive AUTH phase one response...");

    let auth_response = match read_packet_with_sdu(&mut stream, use_large_sdu).await {
        Ok(data) => {
            println!("  Received {} bytes", data.len());
            // Dump raw response for analysis
            println!("  Raw response (first 200 bytes):");
            let hex_data: String = data[..data.len().min(200)].iter().map(|b| format!("{:02x}", b)).collect();
            for i in (0..hex_data.len()).step_by(64) {
                println!("    {}: {}", i/2, &hex_data[i..hex_data.len().min(i+64)]);
            }

            let ptype = data[4];
            println!("  Packet type: {} (4=Refuse, 6=Data, 12=Marker)", ptype);

            if ptype == 6 && data.len() > 10 {
                let msg_type = data[10];
                println!("  Message type: {} (8=Parameter)", msg_type);

                if msg_type == 8 {
                    // Parse the AUTH response key-value pairs
                    let session_data = parse_auth_response(&data[11..]);
                    println!("\n  Parsed AUTH response:");
                    for (k, v) in &session_data.pairs {
                        if v.len() > 40 {
                            println!("    {} = {}...", k, &v[..40]);
                        } else {
                            println!("    {} = {}", k, v);
                        }
                    }
                    println!("    Verifier type: 0x{:04x}", session_data.verifier_type);
                    Some(session_data)
                } else {
                    None
                }
            } else {
                None
            }
        }
        Err(e) => {
            println!("  FAIL: {:?}", e);
            return;
        }
    };

    let session_data = match auth_response {
        Some(sd) => sd,
        None => {
            println!("  FAIL: Could not parse AUTH response");
            return;
        }
    };

    // Step 11: Send AUTH phase two
    println!("\nStep 11: Send AUTH phase two request (seq={})...", seq_num);
    // Try without connect_string first to see if that's the issue
    let connect_string = "";
    // IMPORTANT: Username must be uppercase to match phase one (library converts to uppercase)
    let auth_phase_two = build_auth_phase_two(use_large_sdu, &caps, &session_data, "SYSTEM", connect_string, seq_num);
    seq_num = seq_num.wrapping_add(1);
    let _ = seq_num; // Silence unused warning
    println!("  Auth phase two request ({} bytes)", auth_phase_two.len());
    println!("  First 60 bytes: {:02x?}", &auth_phase_two[..60.min(auth_phase_two.len())]);
    match stream.write_all(&auth_phase_two).await {
        Ok(_) => println!("  OK: AUTH phase two sent"),
        Err(e) => { println!("  FAIL: {:?}", e); return; }
    }
    stream.flush().await.ok();

    // Step 12: Receive AUTH phase two response
    println!("\nStep 12: Receive AUTH phase two response...");
    match read_packet_with_sdu(&mut stream, use_large_sdu).await {
        Ok(data) => {
            println!("  Received {} bytes", data.len());
            println!("  Raw response: {:02x?}", &data[..data.len().min(100)]);
            let ptype = data[4];
            println!("  Packet type: {} (4=Refuse, 6=Data, 12=Marker)", ptype);

            if ptype == 12 {
                // MARKER packet - analyze contents
                if data.len() > 8 {
                    let marker_data = &data[8..];
                    println!("  MARKER data: {:02x?}", marker_data);
                    if marker_data.len() >= 3 {
                        println!("  Marker type: {} (1=Break, 2=Reset, 3=Interrupt)", marker_data[2]);
                    }
                }
                println!("  -> Server sent MARKER (likely protocol error or message format issue)");

                // Try to read more to see if there's an error message following
                println!("\n  Trying to read next packet after MARKER...");
                match timeout(Duration::from_secs(3), read_packet_with_sdu(&mut stream, use_large_sdu)).await {
                    Ok(Ok(more_data)) => {
                        println!("  Got additional {} bytes: {:02x?}", more_data.len(), &more_data[..more_data.len().min(100)]);
                        if more_data.len() > 10 && more_data[4] == 6 {
                            let msg_type = more_data[10];
                            println!("  Message type: {} (4=Error, 8=Parameter)", msg_type);
                            if msg_type == 4 || msg_type == 8 {
                                // Parse response
                                parse_error_response(&more_data[11..]);
                            }
                        }
                    }
                    Ok(Err(e)) => println!("  Error reading: {:?}", e),
                    Err(_) => println!("  Timeout waiting for additional data"),
                }
            } else if ptype == 6 && data.len() > 10 {
                let msg_type = data[10];
                println!("  Message type: {} (4=Error, 8=Parameter, 9=Status)", msg_type);

                if msg_type == 4 {
                    // Error response - parse error details
                    println!("  Error response bytes: {:02x?}", &data[11..data.len().min(100)]);
                    // Try to extract error message
                    let payload = &data[11..];
                    parse_error_response(payload);
                } else if msg_type == 8 {
                    println!("  SUCCESS: Got Parameter response (authentication likely succeeded!)");
                    // Parse the response
                    let response_data = parse_auth_response(&data[11..]);
                    for (k, v) in &response_data.pairs {
                        println!("    {} = {}", k, v);
                    }
                }
            }
        }
        Err(e) => {
            println!("  FAIL: {:?}", e);
        }
    }

    println!("\n=== Handshake completed ===");
}

fn parse_error_response(data: &[u8]) {
    // Try to parse Oracle error response
    // Format is variable, but usually includes error code and message
    if data.len() < 10 {
        println!("  Error data too short");
        return;
    }

    // Look for ASCII text in the response
    let text: String = data.iter()
        .filter(|&&b| b >= 0x20 && b <= 0x7e)
        .map(|&b| b as char)
        .collect();
    if !text.is_empty() {
        println!("  Error text: {}", text);
    }
}

#[derive(Debug, Default)]
struct AuthSessionData {
    pairs: std::collections::HashMap<String, String>,
    verifier_type: u32,
}

fn parse_auth_response(data: &[u8]) -> AuthSessionData {
    let mut result = AuthSessionData::default();
    let mut pos = 0;

    // First byte seems to be an indicator (01)
    if pos >= data.len() { return result; }
    let _indicator = data[pos];
    pos += 1;

    // Second byte is num_params
    if pos >= data.len() { return result; }
    let num_params = data[pos] as usize;
    pos += 1;

    println!("  Parsing {} key-value pairs from position {}", num_params, pos);

    for i in 0..num_params {
        // Key indicator
        if pos >= data.len() { break; }
        let key_indicator = data[pos];
        pos += 1;

        if key_indicator == 0 {
            // No key, skip
            continue;
        }

        // Key length (appears twice - length + length confirmation)
        if pos + 1 >= data.len() { break; }
        let key_len = data[pos] as usize;
        let key_len_confirm = data[pos + 1] as usize;
        pos += 2;

        if key_len != key_len_confirm {
            println!("    Warning: key length mismatch at param {}: {} vs {}", i, key_len, key_len_confirm);
        }

        // Key bytes
        if pos + key_len > data.len() { break; }
        let key = String::from_utf8_lossy(&data[pos..pos + key_len]).to_string();
        pos += key_len;

        // Value indicator
        if pos >= data.len() { break; }
        let value_indicator = data[pos];
        pos += 1;

        let value = if value_indicator != 0 {
            // Value length (appears twice)
            if pos + 1 >= data.len() { break; }
            let value_len = data[pos] as usize;
            let value_len_confirm = data[pos + 1] as usize;
            pos += 2;

            if value_len != value_len_confirm {
                println!("    Warning: value length mismatch at param {}: {} vs {}", i, value_len, value_len_confirm);
            }

            // Value bytes
            if pos + value_len > data.len() { break; }
            let v = String::from_utf8_lossy(&data[pos..pos + value_len]).to_string();
            pos += value_len;
            v
        } else {
            String::new()
        };

        // Flags or verifier_type
        if pos >= data.len() { break; }

        if key == "AUTH_VFR_DATA" {
            // Read verifier type - appears to be variable-length encoded
            // The format seems to be: indicator byte + 2 bytes big-endian
            if pos + 2 < data.len() {
                let b0 = data[pos];
                let b1 = data[pos + 1];
                let b2 = data[pos + 2];

                // If first byte is small, it might be a length indicator
                if b0 < 4 {
                    // Two-byte value follows
                    result.verifier_type = ((b1 as u32) << 8) | (b2 as u32);
                    pos += 3;
                } else {
                    // Single byte value
                    result.verifier_type = b0 as u32;
                    pos += 1;
                }
            }
        } else {
            // Skip flags byte(s) - usually just 00
            if pos < data.len() {
                let flags_byte = data[pos];
                if flags_byte == 0 {
                    pos += 1;
                }
            }
        }

        result.pairs.insert(key, value);
    }

    result
}

fn build_auth_phase_two(large_sdu: bool, caps: &oracle_rs::Capabilities, session_data: &AuthSessionData, username: &str, connect_string: &str, seq_num: u8) -> Vec<u8> {
    // Get session parameters from phase one response
    let auth_sesskey = session_data.pairs.get("AUTH_SESSKEY").cloned().unwrap_or_default();
    let auth_vfr_data = session_data.pairs.get("AUTH_VFR_DATA").cloned().unwrap_or_default();
    let pbkdf2_salt = session_data.pairs.get("AUTH_PBKDF2_CSK_SALT").cloned().unwrap_or_default();
    let vgen_count: u32 = session_data.pairs.get("AUTH_PBKDF2_VGEN_COUNT")
        .and_then(|s| s.parse().ok())
        .unwrap_or(4096);
    let sder_count: u32 = session_data.pairs.get("AUTH_PBKDF2_SDER_COUNT")
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);

    println!("  Using PBKDF2 with {} iterations, sder_count={}", vgen_count, sder_count);
    println!("  Verifier type: 0x{:04x}", session_data.verifier_type);
    println!("  AUTH_SESSKEY hex len: {} chars", auth_sesskey.len());
    println!("  AUTH_VFR_DATA hex len: {} chars", auth_vfr_data.len());
    println!("  AUTH_PBKDF2_CSK_SALT hex len: {} chars", pbkdf2_salt.len());

    let password = b"testpass";
    let verifier_data = hex::decode(&auth_vfr_data).unwrap_or_default();
    let server_sesskey = hex::decode(&auth_sesskey).unwrap_or_default();
    let csk_salt = hex::decode(&pbkdf2_salt).unwrap_or_default();
    println!("  Server sesskey bytes: {}", server_sesskey.len());

    use oracle_rs::crypto::{
        generate_12c_password_hash, decrypt_cbc_256, encrypt_cbc_256_pkcs7,
        generate_session_key_part, generate_12c_combo_key, generate_salt,
        pbkdf2_derive,
    };

    // Step 1: Generate password key using PBKDF2
    // For 12c, the password_key is derived using the verifier_data + "AUTH_PBKDF2_SPEEDY_KEY" as salt
    let mut speedy_salt = verifier_data.clone();
    speedy_salt.extend_from_slice(b"AUTH_PBKDF2_SPEEDY_KEY");
    let password_key = pbkdf2_derive(password, &speedy_salt, vgen_count, 64);

    // Step 2: Generate password hash for session key encryption
    let password_hash = generate_12c_password_hash(password, &verifier_data, vgen_count);
    println!("  Password hash: {} bytes", password_hash.len());

    // Step 3: Decrypt server's session key
    let session_key_part_a = match decrypt_cbc_256(&password_hash, &server_sesskey) {
        Ok(k) => k,
        Err(e) => {
            println!("  Failed to decrypt server session key: {:?}", e);
            return vec![];
        }
    };
    println!("  Decrypted server session key part A: {} bytes", session_key_part_a.len());

    // Step 4: Generate client's session key part (same length as server's)
    let session_key_part_b = generate_session_key_part(session_key_part_a.len());
    println!("  Generated client session key part B: {} bytes", session_key_part_b.len());

    // Step 5: Encrypt client's session key part (uses PKCS7 padding)
    let client_sesskey = match encrypt_cbc_256_pkcs7(&password_hash, &session_key_part_b) {
        Ok(k) => k,
        Err(e) => {
            println!("  Failed to encrypt client session key: {:?}", e);
            return vec![];
        }
    };

    // Step 6: Generate combo key for password encryption
    let combo_key = generate_12c_combo_key(
        &session_key_part_a,
        &session_key_part_b,
        &csk_salt,
        sder_count,
    );
    println!("  Combo key: {} bytes", combo_key.len());

    // Step 7: Generate speedy key (for 12c only, uses PKCS7 padding)
    let speedy_key = if session_data.verifier_type == 0x4815 {
        // speedy_key = encrypt_cbc(combo_key, random_salt + password_key)[:80].hex()
        let random_salt = generate_salt();
        let mut speedy_data = random_salt.to_vec();
        speedy_data.extend_from_slice(&password_key);

        match encrypt_cbc_256_pkcs7(&combo_key, &speedy_data) {
            Ok(encrypted) => {
                let hex = hex::encode_upper(&encrypted[..80.min(encrypted.len())]);
                println!("  Speedy key: {} chars", hex.len());
                hex
            }
            Err(e) => {
                println!("  Failed to encrypt speedy key: {:?}", e);
                String::new()
            }
        }
    } else {
        String::new()
    };

    // Step 8: Encrypt password with combo key (uses PKCS7 padding)
    let salt = generate_salt();
    let mut password_with_salt = salt.to_vec();
    password_with_salt.extend_from_slice(password);
    let encrypted_password = match encrypt_cbc_256_pkcs7(&combo_key, &password_with_salt) {
        Ok(p) => p,
        Err(e) => {
            println!("  Failed to encrypt password: {:?}", e);
            return vec![];
        }
    };

    // Convert to hex strings
    // For 12c: session key is first 64 hex chars (32 bytes)
    let client_sesskey_hex = hex::encode_upper(&client_sesskey[..32.min(client_sesskey.len())]);
    let encrypted_password_hex = hex::encode_upper(&encrypted_password);

    println!("  Client session key hex: {} chars", client_sesskey_hex.len());
    println!("  Encrypted password hex: {} chars", encrypted_password_hex.len());

    // Build the AUTH phase two packet
    build_auth_phase_two_packet(
        large_sdu,
        caps,
        username,
        connect_string,
        &client_sesskey_hex,
        &encrypted_password_hex,
        &speedy_key,
        session_data.verifier_type,
        seq_num,
    )
}

fn build_auth_phase_two_packet(
    large_sdu: bool,
    caps: &oracle_rs::Capabilities,
    username: &str,
    connect_string: &str,
    client_sesskey: &str,
    encrypted_password: &str,
    speedy_key: &str,
    verifier_type: u32,
    seq_num: u8,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1024);
    let username_bytes = username.as_bytes();

    // Data flags
    payload.extend_from_slice(&[0x00, 0x00]);

    // Message type: Function
    payload.push(0x03);

    // Function code: AuthPhaseTwo (115 = 0x73)
    payload.push(115);

    // Sequence number
    payload.push(seq_num);

    // Token number (for TTC field version >= 18)
    if caps.ttc_field_version >= 18 {
        payload.push(0); // UB8 value 0 - single byte encoding
    }

    // User pointer (uint8) - 1 if we have a username
    let has_user = if username_bytes.is_empty() { 0u8 } else { 1u8 };
    payload.push(has_user);

    // User length (UB4)
    write_ub4(&mut payload, username_bytes.len() as u32);

    // Auth mode with password flag (0x101 = LOGON | WITH_PASSWORD)
    write_ub4(&mut payload, 0x101);

    // Auth value list pointer (uint8)
    payload.push(1);

    // Number of key/value pairs (UB4)
    // For 12c with connect_string:
    // AUTH_SESSKEY, AUTH_PBKDF2_SPEEDY_KEY, AUTH_PASSWORD, SESSION_CLIENT_CHARSET,
    // SESSION_CLIENT_DRIVER_NAME, SESSION_CLIENT_VERSION, AUTH_ALTER_SESSION, AUTH_CONNECT_STRING = 8
    let num_pairs = if verifier_type == 0x4815 {
        if connect_string.is_empty() { 7u32 } else { 8u32 }
    } else {
        if connect_string.is_empty() { 6u32 } else { 7u32 }
    };
    write_ub4(&mut payload, num_pairs);

    // Output value list pointer
    payload.push(1);

    // Output value list count pointer
    payload.push(1);

    // Username bytes (if present)
    if has_user == 1 {
        payload.push(username_bytes.len() as u8);
        payload.extend_from_slice(username_bytes);
    }

    // Key-value pairs (order matters!)
    write_key_value(&mut payload, "AUTH_SESSKEY", client_sesskey, 1);

    // For 12c, include speedy key
    if verifier_type == 0x4815 && !speedy_key.is_empty() {
        write_key_value(&mut payload, "AUTH_PBKDF2_SPEEDY_KEY", speedy_key, 0);
    }

    write_key_value(&mut payload, "AUTH_PASSWORD", encrypted_password, 0);

    write_key_value(&mut payload, "SESSION_CLIENT_CHARSET", "873", 0);
    // Match Python's driver name format more closely
    write_key_value(&mut payload, "SESSION_CLIENT_DRIVER_NAME", "oracle-rs thn : 0.1.0", 0);
    // Use same version format as Python oracledb
    write_key_value(&mut payload, "SESSION_CLIENT_VERSION", "54530048", 0);

    // Timezone ALTER SESSION (with null terminator)
    let tz_stmt = "ALTER SESSION SET TIME_ZONE='+00:00'\x00";
    write_key_value(&mut payload, "AUTH_ALTER_SESSION", tz_stmt, 1);

    // Connect string (if provided)
    if !connect_string.is_empty() {
        write_key_value(&mut payload, "AUTH_CONNECT_STRING", connect_string, 0);
    }

    // Build packet with header
    let total_len = 8 + payload.len();
    let mut packet = Vec::with_capacity(total_len);

    if large_sdu {
        packet.extend_from_slice(&(total_len as u32).to_be_bytes());
    } else {
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
    }
    packet.push(0x06); // DATA
    packet.push(0x00); // Flags
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    packet.extend_from_slice(&payload);

    packet
}

fn write_key_value(buf: &mut Vec<u8>, key: &str, value: &str, flags: u32) {
    let key_bytes = key.as_bytes();
    let value_bytes = value.as_bytes();

    // Key length (UB4)
    write_ub4(buf, key_bytes.len() as u32);

    // Key with length prefix
    buf.push(key_bytes.len() as u8);
    buf.extend_from_slice(key_bytes);

    // Value length (UB4)
    write_ub4(buf, value_bytes.len() as u32);

    // Value with length prefix (if non-empty)
    if !value_bytes.is_empty() {
        buf.push(value_bytes.len() as u8);
        buf.extend_from_slice(value_bytes);
    }

    // Flags (UB4)
    write_ub4(buf, flags);
}

fn write_ub4(buf: &mut Vec<u8>, value: u32) {
    // Oracle UB4 format:
    // - 0: write [0]
    // - 1-255: write [1, value]
    // - 256-65535: write [2, high, low]
    // - >65535: write [4, b3, b2, b1, b0]
    if value == 0 {
        buf.push(0);
    } else if value <= 0xFF {
        buf.push(1);
        buf.push(value as u8);
    } else if value <= 0xFFFF {
        buf.push(2);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    } else {
        buf.push(4);
        buf.push((value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    }
}

fn parse_protocol_response(data: &[u8]) -> oracle_rs::Capabilities {
    use oracle_rs::messages::ProtocolMessage;
    use oracle_rs::Capabilities;

    // For now, just dump the response for analysis
    if data.len() > 40 {
        println!("  Protocol response hex dump (bytes 8-100): {:02x?}", &data[8..data.len().min(100)]);
    }

    let mut protocol_msg = ProtocolMessage::new();
    let mut caps = Capabilities::new();

    // Skip the packet header
    let payload = &data[8..];
    if let Err(e) = protocol_msg.parse_response(payload, &mut caps) {
        println!("  Failed to parse protocol response: {:?}", e);
        return caps; // return default caps
    }

    println!("  Parsed TTC field version from server: {}", caps.ttc_field_version);
    println!("  Compile caps[FIELD_VERSION] = {}", caps.compile_caps[7]); // index 7 is FIELD_VERSION
    caps
}

fn build_auth_phase_one(large_sdu: bool, caps: &oracle_rs::Capabilities, seq_num: u8) -> Vec<u8> {
    use oracle_rs::messages::AuthMessage;

    let mut auth = AuthMessage::new("system", b"testpass", "FREEPDB1");
    auth.set_sequence_number(seq_num);
    println!("  Using TTC field version: {} (compile_caps[7] = {})",
             caps.ttc_field_version, caps.compile_caps[7]);

    // Build the packet using the proper library function
    auth.build_request(caps, large_sdu).unwrap().to_vec()
}

fn build_data_types_request(large_sdu: bool, caps: &oracle_rs::Capabilities) -> Vec<u8> {
    use oracle_rs::messages::DataTypesMessage;

    let data_types_msg = DataTypesMessage::new();
    println!("  Using compile_caps[FIELD_VERSION] = {}", caps.compile_caps[7]);

    // Build using the proper library function
    data_types_msg.build_request(caps, large_sdu).unwrap().to_vec()
}

fn build_marker_packet(large_sdu: bool) -> Vec<u8> {
    let payload = [1u8, 0u8, 2u8]; // [1, 0, Reset=2]
    let total_len = 8 + payload.len();
    let mut packet = Vec::with_capacity(total_len);

    if large_sdu {
        packet.extend_from_slice(&(total_len as u32).to_be_bytes());
    } else {
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    }
    packet.push(12); // Packet type: MARKER
    packet.push(0x00); // Flags
    packet.extend_from_slice(&[0x00, 0x00]); // Header checksum
    packet.extend_from_slice(&payload);

    packet
}

async fn read_packet(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    read_packet_with_sdu(stream, false).await
}

async fn read_packet_with_sdu(stream: &mut TcpStream, large_sdu: bool) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 8];
    timeout(Duration::from_secs(10), stream.read_exact(&mut header)).await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))??;

    // In large_sdu mode, first 4 bytes are length; otherwise first 2 bytes
    let packet_len = if large_sdu {
        u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize
    } else {
        u16::from_be_bytes([header[0], header[1]]) as usize
    };
    let remaining = packet_len.saturating_sub(8);

    let mut payload = vec![0u8; remaining];
    if remaining > 0 {
        timeout(Duration::from_secs(5), stream.read_exact(&mut payload)).await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))??;
    }

    let mut full = header.to_vec();
    full.extend(payload);
    Ok(full)
}

fn build_protocol_request_large_sdu(large_sdu: bool) -> Vec<u8> {
    // Build protocol payload - simpler format based on oracle-nio
    let mut payload = Vec::new();

    // Data flags (always present for DATA packets)
    payload.extend_from_slice(&[0x00, 0x00]);
    // Message type: Protocol (1)
    payload.push(0x01);
    // Protocol version (6 = 8.1 and higher)
    payload.push(0x06);
    // Array terminator
    payload.push(0x00);
    // Driver name (null-terminated)
    payload.extend_from_slice(b"oracle-rs\0");

    // Build header with correct format
    let total_len = 8 + payload.len();
    let mut packet = Vec::with_capacity(total_len);

    if large_sdu {
        // Large SDU format: 4-byte length
        packet.extend_from_slice(&(total_len as u32).to_be_bytes());
    } else {
        // Standard format: 2-byte length + 2-byte checksum
        packet.extend_from_slice(&(total_len as u16).to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    }
    packet.push(0x06); // Packet type: DATA
    packet.push(0x00); // Flags
    packet.extend_from_slice(&[0x00, 0x00]); // Header checksum
    packet.extend_from_slice(&payload);

    packet
}
