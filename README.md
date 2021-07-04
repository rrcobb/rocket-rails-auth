# authrs

playing with an authenticating proxy in rust

## run

- start the server with `$ cargo run`
- watch server with `cargo watch --why -d 1 -x run` (requires cargo-watch, `cargo install cargo-watch`)

## what, why

- migrating a system piecewise could founder on authentication
- so, nice to test if the authentication-focused rust microservice can work


## Decrypting cookies in the rails console

```ruby
def config
  secret_key_base = Rails.application.secret_key_base
  cipher_name =  "aes-256-gcm"
  # https://github.com/rails/rails/blob/83217025a171593547d1268651b446d3533e2019/activesupport/lib/active_support/key_generator.rb#L22
  salt   = Rails.application.config.action_dispatch.authenticated_encrypted_cookie_salt
  key_size = OpenSSL::Cipher.new(cipher_name).key_len
  iterations = 1000
  secret = OpenSSL::PKCS5.pbkdf2_hmac_sha1(secret_key_base, salt, iterations, key_size)

  {
    secret_key_base: secret_key_base,
    cipher_name: cipher_name,
    key_size: key_size,
    iterations: iterations,
    secret: secret,
  }
end

def decrypt(encrypted_message)
  encrypted_data, iv, auth_tag = CGI.unescape(encrypted_message).split("--".freeze).map { |v| ::Base64.strict_decode64(v) }
  # puts "encrypted_data, base64 decoded: #{encrypted_data}"
  raise StandardError.new("invalid message") if auth_tag.nil? || auth_tag.bytes.length != 16

  cipher_name, secret = config.values_at(:cipher_name, :secret) 

  cipher = OpenSSL::Cipher.new(cipher_name)
  cipher.decrypt # set mode to decrypt
  cipher.key = secret
  cipher.iv  = iv
  cipher.auth_tag = auth_tag
  cipher.auth_data = ""

  decrypted_data = cipher.update(encrypted_data)
  decrypted_data << cipher.final

  # Rails wraps the actual session information in a package with some metadata
  # https://github.com/rails/rails/blob/cb0a558f42fc6957fac4d2daa16771b72ff7da6e/activesupport/lib/active_support/messages/metadata.rb
  # we just want the internal message
  inner_encoded_message = JSON.load(decrypted_data)["_rails"]["message"]
  JSON.load(Base64.strict_decode64(inner_encoded_message))
end
```

## Implementing that same decryption in Rust

`cookie.rs`

Steps to decrypting a cookie:
- cgi unescape (url decode)
- split on "--"
- base64 decode parts
  - encrypted data, iv, and auth tag are the parts
- check that these
- setup openssl
  - decrypt mode
  - iv, auth_tag
  - secret is OpenSSL::PKCS5.pbkdf2_hmac_sha1(secret_key_base, salt, iterations, key_size)
- openssl decrypt
- parse decrypted as json
- internal encoded message is "._rails.message"
- base64 decode the inner message
- parse that as json
- user id is first element of JSON array at key "warden.user.user.key"

## TODO

- connect diesel to rails db
    - write structs
    - login handler
    - issue own cookies 
      - should they look just like the rails ones? 👀
- extract config to a struct
  - db config
  - secret, salt, iterations, key len, algorithm, 
- make cookie handling into a lib, with tests, instead of a main
   - remove dbgs
   - handle errors well, instead of poorly
   - consider security implications (csrf, timing attacks, what else?); this whole thing might be misguided
       :-)
