# Usage:
# library(plumber)
# pr_run(pr("server.R"), port = 8000)


library(plumber)

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

# data.table to string
dt_to_str = function(dt, max_lines = NULL) {
  
  setDT(dt)
  
  cols = names(dt)
  
  # max_lines must be between 1:nrow(dt)
  if(is.null(max_lines) || is.na(max_lines) || max_lines <= 0 || max_lines > nrow(dt)) {
    max_lines = nrow(dt)
  }

  eval_str = paste0("paste0(",
                    paste0(cols, collapse = ", \",\", "),
                    ", collapse = \"\\n\")")
  cols = paste0(cols, collapse = ",")
  val = dt[1:max_lines, eval(parse(text = eval_str))]
  paste0(cols, "\n", val)
}


# verify
raw = sample(letters, 16, replace = T) %>% paste0(collapse = "") %>% charToRaw
if(!identical(raw, raw %>% raw_to_hexstring %>% hexstring_to_raw)) stop()
if(!identical(raw, raw %>% raw_to_hexstring(url_encode = T) %>% hexstring_to_raw(url_decode = T))) stop()


source("encrypt_decrypt.R")










# for testing purposes
SERVER_DISABLE_SECURITY = F

allowed_clients = c("client_001", "client_py_001")
allowed_params = c("CSV_FILE")
CSV_FILE = NULL
MAIN_DT = NULL
POT_DUPS = NULL


# key management
SERVER_PUB_KEY = NULL
SERVER_PVT_KEY = NULL
CLIENT_PUB_KEY = NULL
SERVER_PVT_KEY_PASSKEY = NULL

# private key storage. Use any passphrase to encrypt server's private key.
server_pvt_key_passphrase = "server"
SERVER_PVT_KEY_PASSKEY = sodium::sha256(charToRaw(server_pvt_key_passphrase))

# Generate server keypair:
SERVER_PVT_KEY = sodium::keygen()
SERVER_PUB_KEY = sodium::pubkey(SERVER_PVT_KEY)
SERVER_PVT_KEY = SERVER_PVT_KEY %>% data_encrypt(passkey = SERVER_PVT_KEY_PASSKEY)


# server-only function. disable_security is for testing purposes only!
encrypt = function(txt, disable_security = SERVER_DISABLE_SECURITY) {
  if(("data.frame" %in% class(txt)) | ("data.table" %in% class(txt))) {
    txt = dt_to_str(txt)
  }
  
  if(disable_security) {
    print("Sending below:")
    print(txt)
    return(txt)
  }
  
  cipher = txt %>% pki_encrypt(SERVER_PVT_KEY, CLIENT_PUB_KEY, SERVER_PVT_KEY_PASSKEY)
  print("Sending below:")
  print(cipher)
  return(cipher)
}

decrypt = function(cipher, disable_security = SERVER_DISABLE_SECURITY) {
  if(disable_security) {
    return(cipher)
  }
  txt = cipher %>% hexstring_to_raw %>% pki_decrypt(SERVER_PVT_KEY, CLIENT_PUB_KEY, SERVER_PVT_KEY_PASSKEY)
  return(txt)
}














#* @get /get-server-pub-key
#* @serializer cat
get_server_pub_key = function(){
  return(SERVER_PUB_KEY)
}










#* @param key
#* @param id
#* @post /set-client-pub-key
#* @serializer cat
set_client_pub_key = function(key, id){
  
  if(missing(key)) {
    dt = data.table(error = "no key provided.")
    return(dt %>% dt_to_str)
  } 
  
  if(missing(id)) {
    dt = data.table(error = "no id provided.")
    return(dt %>% dt_to_str)
  }
  
  CLIENT_PUB_KEY <<- hexstring_to_raw(key)
  id = id %>% decrypt

  if(id %in% allowed_clients) {
    cat("CLIENT_PUB_KEY: ", CLIENT_PUB_KEY, "\n")
    dt = data.table(message = "public key set.")
    # reset all vars
    CSV_FILE <<- NULL
    MAIN_DT  <<- NULL
    POT_DUPS <<- NULL
    return(dt %>% dt_to_str)
  }
  
  # unset CLIENT_PUB_KEY
  CLIENT_PUB_KEY <<- NULL
  dt = data.table(error = "unauthorized.")
  return(dt %>% dt_to_str)
  
}











#* @get /app-name
#* @serializer cat
app_name = function(){
  "PLUMBER_APP" %>% encrypt
}







#* @param paramName
#* @get /get-param
#* @serializer cat
get_param = function(paramName){
  paramName = paramName %>% decrypt
  if(paramName %in% allowed_params) {
    param_evl = eval(parse(text = paramName))
    if(!is.null(param_evl) && !is.na(param_evl)) {
      dt = data.table(paramName = paramName,
                      paramVal = param_evl)
    } else {
      dt = data.table(error = "param is null/NA.")
    }
  } else {
    dt = data.table(error = "invalid param.")
  }
  
  return(dt %>% encrypt)
  
}








#* @param paramName
#* @param paramVal
#* @post /set-param
#* @serializer cat
set_param = function(paramName, paramVal){
  paramName = paramName %>% decrypt
  if(paramName %in% allowed_params) {
    param_evl = eval(parse(text = paramName))
    # set data file
    if(paramName == "CSV_FILE") {
      paramVal = paramVal %>% decrypt
      if(file.exists(paramVal)) {
        CSV_FILE <<- paramVal
        dt = data.table(paramName = paramName,
                 paramVal = paramVal)
      } else {
        dt = data.table(error = "File not found.")
      }
    }
  } else {
    dt = data.table(error = "invalid param.")
  }
  
  return(dt %>% encrypt)
  
}














#* Log some information about the incoming request
#* @filter logger
function(req){
  
  arg_names = names(req$args)
  reqArgs = ""
  for(i in seq_along(req$args)) {
    reqArgs = paste0(reqArgs, arg_names[i], ":", req$args[[i]], ", ")
  }
  reqArgs = str_replace(reqArgs, ",\\s*$", "")
  
  cat("\n\n",
      as.character(Sys.time()), "-",
      "REQUEST_METHOD:", req$REQUEST_METHOD,
      "PATH_INFO:", req$PATH_INFO,
      "args:", reqArgs,
      "\n")

  # bypass security check
  if(SERVER_DISABLE_SECURITY == F) {
    # authorization check
    if(req$PATH_INFO %in% c("/get-server-pub-key", "/set-client-pub-key")) {
      # auth not needed for these! let them pass.
      cat("SERVER_PUB_KEY: ", SERVER_PUB_KEY, "\n")
      cat("CLIENT_PUB_KEY: ", CLIENT_PUB_KEY, "\n")
    } else {
      # client must be authorized for all other end-points
      if(is.null(CLIENT_PUB_KEY)) {
        cat("Auth failed for endpoint: ", req$PATH_INFO, "\n", file = stderr())
        dt = data.table(error = "unauthorized.",
                        message = "client public key not set.")
        return(dt)
      }
      # verify that client has sent correctly encrypted id in the request
      if("id" %in% arg_names) {
        id = req$args$id %>% decrypt
        if(id %in% allowed_clients) {
          # all okay
        } else {
          dt = data.table(error = "unauthorized.",
                          message = "access not allowed for this id.")
          return(dt %>% dt_to_str)
        }
      } else {
        dt = data.table(error = "unauthorized.",
                        message = "id not set in request.")
        return(dt %>% dt_to_str)
      }
    }
  }

  plumber::forward()
}











