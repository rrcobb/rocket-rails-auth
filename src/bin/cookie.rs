extern crate base64;
extern crate openssl;
use std::error;
use percent_encoding::percent_decode_str;
use serde_json::{Value};

fn main() {
    let cookie = "LYl%2BeR%2FGG5fhTeYUQZCoJkXQkhz3Twgu0I%2BCB77qVTpFxNTpzmmUXQXeZGblHiDPJhuq0iKjPqeyIFrKpeaFpI1%2FtPR%2F%2BFh7fY6jdFlq3vc3eq4KS52OLiOWCTaCypzmkwKzF3WfDw921P6FAKpt61F4G0cU7JucOygug9%2F1cR9gLYRZBofeMZyN3tiVLwGO%2FeJADYgr9zGnxsxmFF%2F9h3a5kfnCsI0uvaEF9ABBcq25kIm%2BmLLe0VhUAYTwFBn%2FXzg8sbJ7vitgR%2BrYP%2B6Bur9GcBYf4jc34eOe2vbn6xrBYb%2FFUQDgXtNuUcXQGJxUB5Q9mRitCYkXaG1r7eNLazbatBX5wcDaO%2F4%2FRDWpqALJo8RrOcO72zGRcr6Xaf1ymyMAu%2BiKccp%2BTEfc--BLjarYwcs3tAOZ2L--oLt5fNLia%2BoXG6WaC%2FOg%2FA%3D%3D";
    let result = decrypt_rails_cookie(cookie).unwrap();
    let internal_m = unwrap_decrypted_rails_cookie(&result);
    dbg!(&internal_m);
    match internal_m {
        // user id is first element of JSON array at key "warden.user.user.key"
        Ok(value) => { dbg!(&value["warden.user.user.key"][0][0]); },
        _ => ()
    };
}

fn unwrap_decrypted_rails_cookie(decrypted_cookie: &str) -> Result<Value, Box<dyn error::Error>> {
    let v: Value = serde_json::from_str(decrypted_cookie)?;
    dbg!(&v["_rails"]["message"]);
    let encoded_message = v["_rails"]["message"].as_str().ok_or("missing ._rails.message in cookie")?;
    let decoded_message = String::from_utf8(base64::decode(&encoded_message)?)?;
    Ok(serde_json::from_str(&decoded_message)?)
}

fn generate_secret_key() -> Result<Vec<u8>, openssl::error::ErrorStack>{
    // todo: get from env
    let pass = "f458d32562fed9ccb4cf47a04d9760d9bd89aba4d745b19fa5006fd9b96d894aae3f9f3530af77afb248565e0bbd6b670296ce8817daa959c31d281ad919a8c9".as_bytes();
    let salt = "authenticated encrypted cookie".as_bytes();
    let iter = 1000;
    let hash = openssl::hash::MessageDigest::sha1();
    let mut key = [0; 32];
    match openssl::pkcs5::pbkdf2_hmac(
        pass,
        salt,
        iter,
        hash,
        &mut key
    ) {
        Ok(()) => { Ok(key.to_vec()) }
        Err(stack) => { panic!("issue generating the key") }
    }
}

// strategy: hardcode -> move to config
// move config -> environment
fn decrypt_rails_cookie(cookie: &str) -> Result<String, Box<dyn error::Error>> {
    // url decode
    let percent_decoded = percent_decode_str(cookie).decode_utf8()?;
    // split on "--"
    let parts: Vec<_> = percent_decoded.split("--").collect();
    // will panic on not-enough parts
    // should instead return a different error variant
    // encrypted data, iv, and auth tag are the parts, base64 encoded
    let data = base64::decode(parts[0])?;
    let iv = base64::decode(parts[1])?;
    let tag = base64::decode(parts[2])?;
    // setup openssl
    let cipher = openssl::symm::Cipher::aes_256_gcm();
    let key = generate_secret_key()?;
    let aad: &[u8] = &[]; // empty
    let result = openssl::symm::decrypt_aead(
        cipher,
        &key,
        Some(&iv),
        aad, 
        &data,
        &tag,
    )?;
    Ok(String::from_utf8(result)?)
}
