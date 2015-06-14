-- Copyright (c) 2014 Markus Gutschke
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.


-- A LUA implementation of the server-side portion of the FIDO U2F protocol.
-- This code can be used in the "nginx" web server.
-- For demonstration purposes, it stores all state in a "memcached" instance
-- that must be running on the same machine. For production use, that is
-- almost certainly the wrong approach.
-- Feel free to copy and paste any and all parts of this code into whatever
-- code you already use to authenticate users and to manage their active
-- sessions.

local session   = { }
local u2f       = { }
local cjson     = require "cjson.safe"
local ffi       = require "ffi"
local memcached = require "resty.memcached"
local C         = ffi.C

ffi.cdef [[
  // In order to perform cryptographic operations, we call into the copy of
  // libcrypto.so that is already linked into NGINX.

  typedef struct {
    char _[256]; // This is an extremely conservative upper bound
  } SHA256_CTX;

  struct bignum_st *BN_bin2bn(const char *, int, void *);
  void BN_free(struct bignum_st *);
  void ECDSA_SIG_free(struct ECDSA_SIG_st *);
  void EC_KEY_free(struct ec_key_st *);
  struct ec_key_st *EC_KEY_new_by_curve_name(int);
  int EC_KEY_set_public_key_affine_coordinates(struct ec_key_st *,
                                        struct bignum_st *, struct bignum_st *);
  int ECDSA_do_verify(const char *, int, const struct ECDSA_SIG_st *,
                      struct ec_key_st *);
  void ERR_clear_error(void);
  void EVP_PKEY_free(struct evp_pkey_st *);
  struct ec_key_st *EVP_PKEY_get1_EC_KEY(struct evp_pkey_st *);
  int SHA256_Final(char *, SHA256_CTX *);
  int SHA256_Init(SHA256_CTX *);
  int SHA256_Update(SHA256_CTX *, const char *, size_t);
  void X509_free(struct x509_st *);
  struct evp_pkey_st *X509_get_pubkey(struct x509_st *);
  struct ECDSA_SIG_st *d2i_ECDSA_SIG(struct ECDSA_SIG_st **,
                                     const char **, long);
  struct x509_st *d2i_X509_AUX(struct x509_st **, const char **, long);
]]


-- Define a "switch" function that mimics "C"-style "switch" statements.
local Default, Nil = {}, function () end
local function switch(i)
  return setmetatable({ i }, {
    __call = function(t, cases)
      local item = #t == 0 and Nil or t[1]
      return (cases[item] or cases[Default] or Nil)(item)
    end
  })
end


-- Define a "map" function, as it doesn't exist in LUA, yet.
local function map(array, fnc)
  local ret = { }
  if array then
    for i, v in ipairs(array) do ret[i] = fnc(v) end
  end
  return ret
end


-- Define an "indexOf" function, that searches an array for a particular
-- value. Returns the index where the element was found, or "nil". An optional
-- "fnc" can be used to obtain the key that needs to be compared.
local function indexOf(table, element, fnc)
  if not fnc then fnc = function(o) return o end end
  for idx, value in pairs(table) do
    if fnc(value) == element then
      return idx
    end
  end
  return nil
end


-- Manage sessions and tokens. This is currently done in memcached, but for
-- production use should be backed by a fully persistent data base.
-- N.B. storing cleartext passwords in the data base is probably not a good
-- idea in production. Instead, the code should be rewritten to tie into an
-- existing authentication and session management solution.
local function database()
  local memc, err = memcached:new()
  if not memc then
    return nil, err
  end
  memc:set_timeout(1000)
  local ok, err = memc:connect("127.0.0.1", 11211)
  if not ok then
    return nil, err
  end
  return {
    set    = function(s, k, v, t, f) return memc:set(k, v, t, f)           end,
    get    = function(s, k)          return memc:get(k)                    end,
    delete = function(s, k)          return memc:delete(k)                 end,
    close  = function(s)             return memc:set_keepalive(10000, 100) end,
  }
end


-- Set temporary state for token registration.
function session.setRegState(key, credentials)
  local db, err = database()
  if db then
    db:set("REG:" .. key, cjson.encode(credentials), 300)
    db:close()
  end
  return err
end


-- Retrieve temporary state for token registration.
function session.getAndDeleteRegState(key)
  local db, err = database()
  if db then
    local credentials, err = db:get("REG:" .. key)
    db:delete("REG:" .. key)
    db:close()
    return credentials and cjson.decode(credentials) or { }, err
  end
  return nil, err
end


-- Set temporary state for authentication handling.
function session.setAuthState(key, session)
  local db, err = database()
  if db then
    db:set("AUTH:" .. key, cjson.encode(session), 300)
    db:close()
  end
  return err
end


-- Retrieve temporary state for authentication handling.
function session.getAndDeleteAuthState(key)
  local db, err = database()
  if db then
    local session, err = db:get("AUTH:" .. key)
    db:delete("AUTH:" .. key)
    db:close()
    return session and cjson.decode(session) or { }, err
  end
  return nil, err
end


-- Set information about a user account.
function session.setAccountData(user, account)
  local db, err = database()
  if db then
    db:set("ACCOUNT:" .. user, cjson.encode(account))
    db:close()
  end
  return err
end


-- Retrieve information about a user account.
function session.getAccountData(user)
  local db, err = database()
  if db then
    local account, err = db:get("ACCOUNT:" .. user)
    db:close()
    return account and cjson.decode(account) or { }, err
  end
  return nil, err
end


-- Encode a string in websafe base64.
local function encodeBase64(s)
  s = ngx.encode_base64(s):gsub("([+/=])",
        function(c) return ({ ["+"] = "-", ["/"] = "_", ["="] = "" })[c] end)
  return s
end


-- Decode a websafe base64 encoded string.
local function decodeBase64(s)
  s = s:gsub("([-_])", function(c) return ({ ["-"] = "+", ["_"] = "/" })[c] end)
  return ngx.decode_base64(s)
end


-- Determine the "origin" (aka "facet") of our virtual server.
local function origin()
  local origin = "https://" .. ngx.var.server_name
  local port = ngx.var.server_port
  if port ~= "443" then origin = origin .. ":" .. ngx.var.server_port end
  return origin
end


-- Encode a status message as JSON and return it to the browser.
local function retJSON(obj)
  ngx.header["Content-Type"] = "application/json;charset=UTF-8"
  ngx.print((cjson.encode(obj)))
  return ngx.exit(ngx.HTTP_OK)
end


-- Return a status code and a human-readable progress or error message.
local function retStatus(status, msg)
  return retJSON({ status = status, msg = msg })
end


-- Given a DER encoded certificate, compute the length of the certificate. In
-- case of error, return zero. This is essentially a very stripped down DER
-- parser that only knows about parsing length of the very first entry in the
-- certificate. This entry is typically a container for the rest of the data.
local function derLen(der)
  local ret = 0
  if bit.band(der:byte(1), 31) > 30 then return 0 end
  if der:byte(2) < 128 then
    ret = der:byte(2) + 2
  elseif der:byte(2) == 0x82 then
    ret = der:byte(3)*256 + der:byte(4) + 4
  elseif der:byte(2) == 0x83 then
    ret = der:byte(3)*65536 + der:byte(4)*256 + der:byte(5) + 5
  end
  if ret > #der then
    return 0
  else
    return ret
  end
end


-- NGINX's Lua module doesn't have support for SHA256 signatures. Fortunately,
-- we can just call into libcrypto.so to compute this type of hash.
local function sha256(dat)
  local ctx = ffi.new("SHA256_CTX[1]")
  C.SHA256_Init(ctx)
  C.SHA256_Update(ctx, ffi.new("const char *", dat), #dat)
  local out = ffi.new("char [33]")
  C.SHA256_Final(out, ctx)
  return ffi.string(out, 32)
end


-- Obtain some random data that can be passed to the client as a challenge
-- parameter. This data is also later used as a handle to retrieve state
-- needed for continuing requests.
local function computeRandomData()
  local handle, msg, err = io.open("/dev/urandom", "r")
  if err then
    return retStatus("error", "Internal error; failed to obtain random bytes.")
  end
  local rnd = handle:read(16)
  handle:close()
  if #rnd ~= 16 then
    return retStatus("error", "Internal error; failed to obtain random bytes.")
  end
  return nil, encodeBase64(rnd)
end


-- Compute a random challenge that the browser will eventually sign for us.
-- This string is also used to maintain session state. It can later allow us
-- to look up the user id and password associated with a U2F token registration.
local function regChallenge(req)
  -- Sanity check the request parameters.
  if not (req and req.user and type(req.user) == "string" and
          req.password and type(req.password) == "string") then
    return retStatus("error", "Invalid request received.")
  end

  -- User and password must be non-empty.
  if #req.user < 1 or #req.password < 1 then
    return retStatus("error", "User and password fields cannot be blank.")
  end

  -- Store state, so that we can look it up again later.
  local err, rnd = computeRandomData()
  if err then return err end
  session.setRegState(rnd, {
    user = req.user,
    password = req.password,
  })

  -- Retrieve data on any tokens that have previously been registered. This
  -- helps us to avoid registering the same token multiple times.
  local account = session.getAccountData(req.user) or { }
  local keyHandles = { }
  if account.password == nil or account.password == req.password then
    -- Don't needlessly leak information about the user, if the password
    -- couldn't be matched. Let the user continue with the registration process,
    -- and then deny it later.
    -- N.B. in a production server this would be handled differently. Only an
    -- actively logged in user should be able to add new tokens to an account.
    keyHandles = map(account.tokens or { },
                     function(obj) return encodeBase64(obj.keyHandle) end)
  end

  -- Return random challenge to caller.
  return retJSON({
    status = "ok",
    appId = origin(),
    challenge = rnd,
    keyHandles = keyHandles,
  })
end


-- Parse a registration request. The HTTP request includes a lot of parameters
-- that all need to be validated, before being able to extract the cryptographic
-- payload.
local function getSignedRegistrationRequest(req)
  -- The user provided us with their user id and password when they initiated
  -- the registration request. We temporarily stored this data and can retrieve
  -- it by looking at the random challenge that we shared with the client.
  local credentials
  if req and req.challenge then
    credentials = session.getAndDeleteRegState(req.challenge)
  end
  if credentials == nil or
     credentials.user == nil or credentials.password == nil then
    return retStatus("error", "Transaction expired. Try again.")
  end

  -- Do some basic sanity checking of the request.
  if not (req.clientData and type(req.clientData) == "string" and
          req.registrationData and type(req.registrationData) == "string" and
          req.challenge and type(req.challenge) == "string" and
          req.version == "U2F_V2" and req.appId == origin()) then
    return retStatus("error", "Invalid request received.")
  end
  if #req.challenge ~= 22 then
    return retStatus("error", "Invalid request received.")
  end

  -- Decode the client data and again perform some basic sanity checking.
  local clientDataStr = decodeBase64(req.clientData)
  local clientData = cjson.decode(clientDataStr)
  if not (clientData and
          clientData.typ == "navigator.id.finishEnrollment" and
          clientData.challenge == req.challenge and
          clientData.origin == origin()) then
    return retStatus("error", "Invalid request received.")
  end

  -- Decode the registration data and again perform some basic sanity checking.
  local registrationData = decodeBase64(req.registrationData)
  if registrationData:byte(1) ~= 5 or registrationData:byte(2) ~= 4 then
    return retStatus("error", "Invalid request received.")
  end

  -- Extract the digest (i.e. the data that was signed by the token), the
  -- certificate (used for signing), and the cryptographic signature. Return
  -- all of this data to the caller.
  local keyPub = registrationData:sub(2, 66)
  local keyHandle = registrationData:sub(68, 68 + registrationData:byte(67) - 1)
  local digest = sha256("\x00" .. sha256(req.appId) .. sha256(clientDataStr) ..
                        keyHandle .. keyPub)
  local certAndSignature = registrationData:sub(68 + #keyHandle)
  local certificateLen = derLen(certAndSignature)

  return nil, credentials, keyHandle, keyPub, digest,
         certAndSignature:sub(1,certificateLen),
         certAndSignature:sub(certificateLen+1)
end


-- Register a new U2F token to an account. We must verify the cryptographic
-- signature, before we allow registration.
local function register()
  -- Make sure our API was called with a POST request. Then retrieve the
  -- parameters from the request body.
  if ngx.req.get_method() ~= "POST" or
     not ngx.req.get_headers().content_type:find("application/json") or
     ngx.var.scheme ~= "https" then
    return retStatus("error", "Invalid request received.")
  end
  ngx.req.read_body()

  -- Decode request parameters and extract data needed to register the
  -- token.
  local req = cjson.decode(ngx.req.get_body_data())
  local err, credentials, keyHandle, keyPub, digest, certificate, signature =
        getSignedRegistrationRequest(req)
  if err then return err end
  local account = session.getAccountData(credentials.user) or { }
  if account.password ~= nil and account.password ~= credentials.password then
    return retStatus("error", "Access denied.")
  end

  -- Call into OpenSSL to verify the NIST Curve P-256 ECDSA signature.
  C.ERR_clear_error()
  local key, sig
  local certificatePtr = ffi.new("const char *", certificate)
  local ptr = ffi.new("const char*[1]", certificatePtr)
  local cert = ffi.gc(C.d2i_X509_AUX(nil, ptr, #certificate), C.X509_free)
  if cert ~= nil and ptr[0] == certificatePtr + #certificate then
    local pubkey = ffi.gc(C.X509_get_pubkey(cert), C.EVP_PKEY_free)
    if pubkey ~= nil then
      key = ffi.gc(C.EVP_PKEY_get1_EC_KEY(pubkey), C.EC_KEY_free)
      if key ~= nil then
        local signaturePtr = ffi.new("const char *", signature)
        ptr = ffi.new("const char*[1]", signaturePtr)
        sig = ffi.gc(C.d2i_ECDSA_SIG(nil, ptr, #signature), C.ECDSA_SIG_free)
      end
    end
  end
  if sig == nil then
    C.ERR_clear_error()
    return retStatus("error", "Invalid request received.")
  end

  -- If the signature can be verified, add the new key handle and public key
  -- to the list of known tokens for this particular user account.
  if C.ECDSA_do_verify(ffi.new("const char *", digest),
                       #digest, sig, key) == 1 then
    -- If user doesn't exist yet, allow them to set the initial password.
    -- N.B. in production environments, a more sophisticated policy is needed.
    if account.password == nil then account.password = credentials.password end
    if account.tokens == nil then account.tokens = { } end
    table.insert(account.tokens, { keyHandle = keyHandle, keyPub = keyPub })
    session.setAccountData(credentials.user, account)
    return retStatus("ok", "Registered U2F token for user '" ..
                           credentials.user .. "'.")
  end
  return retStatus("error",
                   "U2F token produced invalid cryptographic signature.")
end


-- Compute a random challenge string that is needed to complete a authentication
-- request.
local function authChallenge(req)
  -- Sanity check the request parameters, then retrieve the keyHandle for this
  -- particular user.
  local keyHandles = { }
  local tokens
  if req and req.user and type(req.user) == "string" and
     req.password and type(req.password) == "string" then
    account = session.getAccountData(req.user) or { }
    keyHandles = map(account.tokens or { },
                     function(o) return encodeBase64(o.keyHandle) end)
  end
  if #keyHandles <= 0 then
    return retStatus("error", "No tokens registered for this user.")
  end

  -- Compute random challenge and return it to the caller.
  local err, rnd = computeRandomData()
  if err then return err end
  session.setAuthState(rnd, {
    user = req.user,
    password = req.password,
    tokens = account.tokens,
    appId = origin(),
  })
  return retJSON({
    status = "ok",
    appId = origin(),
    challenge = rnd,
    keyHandles = keyHandles,
  })
end


-- Parse a authentication signature request. The HTTP request includes a lot of
-- parameters that all need to be validated, before being able to verify
-- the cryptographic payload.
local function getAuthSignatureData(req)
  -- The user provided us with their user id and password when they initiated
  -- the authentication request. We temporarily stored this data and can
  -- retrieve it by looking at the random challenge that we shared with the
  -- client.
  local clientData, clientDataStr
  if req and req.clientData and type(req.clientData) == "string" then
    clientDataStr = decodeBase64(req.clientData) or ""
    clientData = cjson.decode(clientDataStr) or { }
    if not clientData or not clientData.challenge or
       type(clientData.challenge) ~= "string" or
       #clientData.challenge ~= 22 then
      clientData = nil
    end
  end
  if not clientData or
     not clientData.challenge or type(clientData.challenge) ~= "string" or
     not clientData.origin or type(clientData.origin) ~= "string" then
    return retStatus("error", "Invalid request received.")
  end
  local credentials = session.getAndDeleteAuthState(clientData.challenge)
  if not credentials or
     credentials.user == nil or credentials.password == nil or
     credentials.tokens == nil then
    return retStatus("error", "Transaction expired. Try again. ")
  end

  -- Do some basic sanity checking of the request.
  if not (req.keyHandle and type(req.keyHandle) == "string" and
          req.signatureData and type(req.signatureData) == "string" and
          clientData.origin == origin()) then
    return retStatus("error", "Invalid request received.")
  end
  local i = indexOf(credentials.tokens, req.keyHandle,
                    function(o)
                      return encodeBase64(o.keyHandle)
                    end)
  if not i then return retStatus("error", "Invalid request received.") end
  local keyPub = credentials.tokens[i].keyPub

  -- Extract information from the "signatureData".
  local signatureData = decodeBase64(req.signatureData)
  if not signatureData or #signatureData < 6 or
     signatureData:byte(1) ~= 1 then
    return retStatus("error", "Invalid request received.")
  end
  local counter = ((signatureData:byte(2) *256 +
                    signatureData:byte(3))*256 +
                    signatureData:byte(4))*256 +
                    signatureData:byte(5)
  local signature = signatureData:sub(6)

  -- Compute the digest (i.e. the data that was signed by the token).
  local digest = sha256(sha256(credentials.appId) .. signatureData:sub(1, 5) ..
                        sha256(clientDataStr))

  return nil, credentials, keyPub, counter, signature, digest
end


-- Authenticate a user that identified with their U2F token.
local function authenticate()
  -- Make sure our API was called with a POST request. Then retrieve the
  -- parameters from the request body.
  if ngx.req.get_method() ~= "POST" or
     not ngx.req.get_headers().content_type:find("application/json") or
     ngx.var.scheme ~= "https" then
    return retStatus("error", "Invalid request received.")
  end
  ngx.req.read_body()

  -- Decode request parameters and extract data needed to authenticate
  -- the user.
  local req = cjson.decode(ngx.req.get_body_data())
  local err, credentials, keyPub, counter, signature, digest =
        getAuthSignatureData(req)
  if err then return err end
  local account = session.getAccountData(credentials.user) or { }
  if account.password ~= credentials.password then
    return retStatus("error", "Access denied.")
  end
  if account.counter and account.counter >= counter then
    return retStatus("error",
               "Replay attack detected. This U2F token has been tampered with!")
  else
    account.counter = counter
    session.setAccountData(credentials.user, account)
  end

  -- Call into OpenSSL to verify the NIST Curve P-256 ECDSA signature.
  C.ERR_clear_error()
  local sig
  local key = ffi.gc(C.EC_KEY_new_by_curve_name(415 --[[NID_X9_62_prime256v1]]),
                     C.EC_KEY_free)
  if key ~= nil then
    local ptr = ffi.new("const char *", keyPub)
    local x = ffi.gc(C.BN_bin2bn(ptr+ 1, 32, nil), C.BN_free)
    local y = ffi.gc(C.BN_bin2bn(ptr+33, 32, nil), C.BN_free)
    if x ~= nil and y ~= nil and
      C.EC_KEY_set_public_key_affine_coordinates(key, x, y) ~= 0 then
      local signaturePtr = ffi.new("const char *", signature)
      ptr = ffi.new("const char*[1]", signaturePtr)
      sig = ffi.gc(C.d2i_ECDSA_SIG(nil, ptr, #signature), C.ECDSA_SIG_free)
    end
  end
  if sig == nil then
    C.ERR_clear_error()
    return retStatus("error", "Invalid request received.")
  end

  -- If the signature can be verified, the user has successfully been
  -- authenticated.
  if C.ECDSA_do_verify(ffi.new("const char *", digest),
                       #digest, sig, key) == 1 then
    return retStatus("ok", "Authenticated user '" .. credentials.user .. "'.")
  end
  return retStatus("error", "Access denied")
end


-- Both registration requests and authentication requests start by computing a
-- random challenge string.
local function challenge()
  -- Make sure our API was called with a POST request. Then retrieve the
  -- parameters from the request body.
  if ngx.req.get_method() ~= "POST" or
     not ngx.req.get_headers().content_type:find("application/json") or
     ngx.var.scheme ~= "https" then
    return retStatus("error", "Invalid request received.")
  end
  ngx.req.read_body()
  local req = cjson.decode(ngx.req.get_body_data())

  -- Sanity check the request parameters.
  if req and req.authenticate then
    return authChallenge(req)
  else
    return regChallenge(req)
  end
end


-- NGINX content handler that de-multiplexes the different request types.
function u2f.content(req)
  ngx.header["Content-Type"] = "text/plain"
  return switch(req) {
    challenge    = challenge,
    register     = register,
    authenticate = authenticate,
    [Default]    = function() return ngx.exit(ngx.HTTP_NOT_FOUND) end,
  }
end

return u2f
