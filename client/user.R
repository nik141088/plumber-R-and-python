

# for testing purposes
CLIENT_DISABLE_SECURITY = F


source("encrypt_decrypt.R")
# setwd("client/")


# URL encode and decode
ENC = function(str) {
  return(URLencode(str, reserved = T))
}

DEC = function(str) {
  return(URLdecode(str))
}



# hex-string to raw
hexstring_to_raw = function(str, url_decode = F) {
  
  if(url_decode) {
    str = DEC(str)
  }
  
  # remove all non-hex chars (note that the caret `^` here designates negation)
  str = str_replace_all(str, "[^0-9a-fA-F]", "")
  
  # str must be even length
  if(nchar(str) %% 2 != 0) {
    stop("Error in hexstring!")
  }
  
  rng = seq(from = 1, to = nchar(str), by = 2)
  str = sapply(rng, function(i) substr(str, i, i+1))
  
  paste0("0x", str) %>% as.integer %>% as.raw
}

# raw to hex-string
raw_to_hexstring = function(raw, url_encode = F) {
  raw %>%
    as.integer %>%
    sprintf("%0.2x", .) %>%
    paste0(collapse = "") %>%
    ifelse(url_encode, ENC(.), .)
}




CLIENT_ID = "client_001" # for authorization

# key management
CLIENT_PUB_KEY = NULL
CLIENT_PVT_KEY = NULL
SERVER_PUB_KEY = NULL
CLIENT_PVT_KEY_PASSKEY = NULL

# private key storage. Use any passphrase to encrypt client's private key.
client_pvt_key_passphrase = "user_client"
CLIENT_PVT_KEY_PASSKEY = sodium::sha256(charToRaw(client_pvt_key_passphrase))

# Generate client keypair:
CLIENT_PVT_KEY = sodium::keygen()
CLIENT_PUB_KEY = sodium::pubkey(CLIENT_PVT_KEY)
CLIENT_PVT_KEY = CLIENT_PVT_KEY %>% data_encrypt(passkey = CLIENT_PVT_KEY_PASSKEY)


# client-only function
encrypt = function(txt, disable_security = CLIENT_DISABLE_SECURITY) {
  if(disable_security) {
    return(txt)
  }
  cipher = txt %>% pki_encrypt(CLIENT_PVT_KEY, SERVER_PUB_KEY, CLIENT_PVT_KEY_PASSKEY)
  return(cipher %>% raw_to_hexstring)
}

decrypt = function(cipher, disable_security = CLIENT_DISABLE_SECURITY) {
  if(disable_security) {
    return(cipher)
  }
  txt = cipher %>% hexstring_to_raw %>% pki_decrypt(CLIENT_PVT_KEY, SERVER_PUB_KEY, CLIENT_PVT_KEY_PASSKEY)
  return(txt)
}







# httr query
EXEC_API = function(api, type, argName = NULL, argVal = NULL, print = T, cat_res = F) {
  
  if(!(type %in% c("GET", "POST"))) {
    stop("Only GET and POST are supported!")
  }
  
  query = paste0("http://127.0.0.1:8000/", api)

  # add client id in all requests
  if(is.null(argName)) {
    argName = "id"
    argVal = CLIENT_ID
  } else {
    argName = c(argName, "id")
    argVal = c(argVal, CLIENT_ID)
  }
  
  params = c()
  if(!is.null(argName) && !is.null(argVal) && length(argName) == length(argVal)) {
    query = paste0(query, "?")
    argValEnc = rep(NA, length(argVal))
    for(i in 1:length(argName)) {
      # encrypt argVal
      argValEnc[i] = argVal[i] %>% encrypt
      params = c(params, paste0(argName[i] %>% ENC, "=", argValEnc[i] %>% ENC) )
    }
    params = paste0(params, collapse = "&")
  }
  
  query = paste0(query, params)
  
  if(print) {
    cat(crayon::green("Executing", type, "on URL:", query, "\n"))
  }
  
  if(type == "GET") {
    res = httr::GET(query)
  }
  
  if(type == "POST") {
    res = httr::POST(query)
  }
  
  res_val = res$content %>% rawToChar
  
  if(cat_res) {
    cat("plain-text:", "\n", res_val, "\n")
  }
  
  dec_val = res_val %>% decrypt
  
  if(cat_res) {
    cat("decrypted:", "\n", dec_val, "\n")
  }
  
  return(dec_val)
  
}









# get server public key
SERVER_PUB_KEY <<- httr::GET("http://127.0.0.1:8000/get-server-pub-key")$content %>% rawToChar %>% hexstring_to_raw



# un-authorized requests!
httr::GET("http://127.0.0.1:8000/app-name")$content %>% rawToChar %>% cat
httr::POST("http://127.0.0.1:8000/set-param?paramName=CSV_FILE&paramVal=C%3A%2FUsers%2Fnikhi%2FDocuments%2Ftmp.csv")$content %>% rawToChar %>% cat





# set client public key on server. Also share your client id.
client_pub_key__ = CLIENT_PUB_KEY %>% raw_to_hexstring %>% ENC
enc_client_id__  = CLIENT_ID %>% encrypt %>% ENC
res = httr::POST(paste0("http://127.0.0.1:8000/set-client-pub-key?",
                        "key=", client_pub_key__,
                        "&id=", enc_client_id__))
remove(client_pub_key__, enc_client_id__)
cat(res$content %>% rawToChar)






# requests without client id
httr::GET("http://127.0.0.1:8000/app-name")$content %>% rawToChar

# requests with incorrect client id
httr::GET("http://127.0.0.1:8000/app-name?id=abcd")$content %>% rawToChar

# requests with correct client id but no encryption
httr::GET(paste0("http://127.0.0.1:8000/app-name?id=",
                 CLIENT_ID %>% ENC))$content %>% rawToChar

# requests with incorrect client id but encryption done
httr::GET(paste0("http://127.0.0.1:8000/app-name?id=",
                 "abcd" %>% encrypt %>% ENC))$content %>% rawToChar

# correct client-id and encryption but no decryption of o/p!
httr::GET(paste0("http://127.0.0.1:8000/app-name?id=",
                 CLIENT_ID %>% encrypt %>% ENC))$content %>% rawToChar

# properly decrypted requests!
httr::GET(paste0("http://127.0.0.1:8000/app-name?id=",
                 CLIENT_ID %>% encrypt %>% ENC))$content %>% rawToChar %>% decrypt






EXEC_API("app-name", "GET")
EXEC_API("get-param", "GET", "paramName", "CSV_FILE")





EXEC_API("set-param", "POST",
         c("paramName", "paramVal"),
         c("CSV_FILE", "C:/Users/nikhi/Documents/tmp.csv"))
EXEC_API("get-param", "GET", "paramName", "CSV_FILE")























