

# this is used for encryption
pki_encrypt = function(txt, pvt_key, pub_key, passkey) {
  pvt_key_decrypt = data_decrypt(pvt_key, passkey = passkey)
  raw = charToRaw(txt)
  cipher = sodium::auth_encrypt(raw, pvt_key_decrypt, pub_key)
  nonce = attr(cipher, "nonce")
  attr(cipher, "nonce") = NULL
  return(c(nonce, cipher))
}


# this is used for decryption
pki_decrypt = function(cipher, pvt_key, pub_key, passkey) {
  pvt_key_decrypt = data_decrypt(pvt_key, passkey = passkey)
  nonce = cipher[1:24]
  cipher = cipher[25:length(cipher)]
  raw = sodium::auth_decrypt(cipher, pvt_key_decrypt, pub_key, nonce = nonce)
  txt = rawToChar(raw)
  return(txt)
}


# this is only used for encrypting server's private key
data_encrypt = function(raw, passkey) {
  cipher = sodium::data_encrypt(raw, passkey)
  nonce = attr(cipher, "nonce")
  attr(cipher, "nonce") = NULL
  return(c(nonce, cipher))
}


# this is only used for decrypting server's private key
data_decrypt = function(cipher, passkey) {
  nonce = cipher[1:24]
  cipher = cipher[25:length(cipher)]
  raw = sodium::data_decrypt(cipher, passkey, nonce = nonce)
  return(raw)
}

