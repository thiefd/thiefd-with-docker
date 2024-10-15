local socket = require "socket"
local ssl = require "ssl"
local https = require "ssl.https"
local ltn12 = require "ltn12"
local lanes = require "lanes".configure()
local os = require "os"

-- Utility functions for bitwise operations
local function bit_not(n) return 4294967295 - n end
local function bit_and(a, b) return ((a+b) - bit_xor(a,b))/2 end
local function bit_or(a, b) return bit_not(bit_and(bit_not(a), bit_not(b))) end
local function bit_xor(a, b) return bit_and(bit_or(a,b), bit_not(bit_and(a,b))) end
local function bit_rshift(a, b) return math.floor(a / 2^b) end
local function bit_lshift(a, b) return (a * 2^b) % 4294967296 end
local function bit_ror(a, b)
    local s = a % 4294967296
    s = bit_or(bit_rshift(s, b), bit_lshift(s, (32-b)))
    return s % 4294967296
end

-- SHA-256 implementation in pure Lua
local function sha256(message)
    local h0, h1, h2, h3, h4, h5, h6, h7 = 
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

    local k = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    }

    local function preprocess(msg)
        local len = #msg
        msg = msg .. string.char(0x80)
        local bits = (len * 8)
        local padding = (56 - (len + 1) % 64) % 64
        msg = msg .. string.rep("\0", padding)
        msg = msg .. string.char(
            bit_rshift(bits, 56) % 256, bit_rshift(bits, 48) % 256,
            bit_rshift(bits, 40) % 256, bit_rshift(bits, 32) % 256,
            bit_rshift(bits, 24) % 256, bit_rshift(bits, 16) % 256,
            bit_rshift(bits, 8) % 256, bits % 256
        )
        return msg
    end

    local function process_chunk(chunk)
        local w = {}
        for i = 1, 16 do
            w[i] = bit_lshift(chunk:byte(i*4-3), 24) +
                   bit_lshift(chunk:byte(i*4-2), 16) +
                   bit_lshift(chunk:byte(i*4-1), 8) +
                   chunk:byte(i*4)
        end

        for i = 17, 64 do
            local s0 = bit_xor(bit_ror(w[i-15], 7), bit_ror(w[i-15], 18), bit_rshift(w[i-15], 3))
            local s1 = bit_xor(bit_ror(w[i-2], 17), bit_ror(w[i-2], 19), bit_rshift(w[i-2], 10))
            w[i] = (w[i-16] + s0 + w[i-7] + s1) % 4294967296
        end

        local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for i = 1, 64 do
            local s1 = bit_xor(bit_ror(e, 6), bit_ror(e, 11), bit_ror(e, 25))
            local ch = bit_xor(bit_and(e, f), bit_and(bit_not(e), g))
            local temp1 = (h + s1 + ch + k[i] + w[i]) % 4294967296
            local s0 = bit_xor(bit_ror(a, 2), bit_ror(a, 13), bit_ror(a, 22))
            local maj = bit_xor(bit_and(a, b), bit_and(a, c), bit_and(b, c))
            local temp2 = (s0 + maj) % 4294967296

            h = g
            g = f
            f = e
            e = (d + temp1) % 4294967296
            d = c
            c = b
            b = a
            a = (temp1 + temp2) % 4294967296
        end

        h0 = (h0 + a) % 4294967296
        h1 = (h1 + b) % 4294967296
        h2 = (h2 + c) % 4294967296
        h3 = (h3 + d) % 4294967296
        h4 = (h4 + e) % 4294967296
        h5 = (h5 + f) % 4294967296
        h6 = (h6 + g) % 4294967296
        h7 = (h7 + h) % 4294967296
    end

    message = preprocess(message)
    for i = 1, #message, 64 do
        process_chunk(message:sub(i, i+63))
    end

    return string.format("%08x%08x%08x%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4, h5, h6, h7)
end

-- HMAC-SHA256 implementation in pure Lua
local function hmac_sha256(key, message)
    local block_size = 64
    local opad = string.rep(string.char(0x5c), block_size)
    local ipad = string.rep(string.char(0x36), block_size)

    if #key > block_size then
        key = sha256(key)
    end

    key = key .. string.rep(string.char(0), block_size - #key)

    local outer = bit_xor(key, opad)
    local inner = bit_xor(key, ipad)

    return sha256(outer .. sha256(inner .. message))
end

-- Print ASCII Logo
local function print_logo()
    local logo = [[
████████╗██╗  ██╗██╗███████╗███████╗██████╗ 
╚══██╔══╝██║  ██║██║██╔════╝██╔════╝██╔══██╗
   ██║   ███████║██║█████╗  █████╗  ██║  ██║
   ██║   ██╔══██║██║██╔══╝  ██╔══╝  ██║  ██║
   ██║   ██║  ██║██║███████╗██║     ██████╔╝
   ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚═╝     ╚═════╝ 
   ==============================WITH DOCKER
    ]]
    print(logo)
end

local function simple_json_encode(data)
    if type(data) == "string" then
        return '"' .. data:gsub('"', '\\"'):gsub("\n", "\\n") .. '"'
    elseif type(data) == "table" then
        local json = "{"
        for k, v in pairs(data) do
            if type(k) == "string" then
                json = json .. '"' .. k .. '":'
            else
                json = json .. "[" .. tostring(k) .. "]:"
            end
            json = json .. simple_json_encode(v) .. ","
        end
        return json:sub(1, -2) .. "}"
    else
        return tostring(data)
    end
end

local function debug_print(msg)
    print(os.date("%Y-%m-%d %H:%M:%S") .. " [DEBUG] " .. msg)
end

local function error_print(msg)
    print(os.date("%Y-%m-%d %H:%M:%S") .. " [ERROR] " .. msg)
end

local DOCKER_IMAGE
local FORWARD_MODE = false
local FORWARD_WEBHOOK_URL
local SERVER_CERT = "certs/server.crt"
local SERVER_KEY = "certs/server.key"
local CA_CERT = "certs/ca.crt"
local HMAC_SECRET = "your_secret_key_here" -- Replace with a strong, unique secret

local function execute_docker_command(docker_image, command)
    if not docker_image or docker_image == "" then
        error_print("Docker image name is empty")
        return "Error: Empty Docker image name"
    end
    if not command or command == "" then
        error_print("Attempt to execute empty command")
        return "Error: Empty command"
    end
    debug_print("Executing Docker command: " .. command)
    local cmd = string.format("docker run --rm %s %s", docker_image, command)
    local handle = io.popen(cmd)
    local result = handle:read("*a")
    handle:close()
    debug_print("Docker execution completed")
    return result
end

local function send_webhook(url, data)
    debug_print("Sending webhook to: " .. url)
    local payload = simple_json_encode({text = data})
    local response = {}
    
    local request, code = https.request{
        url = url,
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = #payload
        },
        source = ltn12.source.string(payload),
        sink = ltn12.sink.table(response)
    }
    
    debug_print("Webhook sent, response code: " .. tostring(code))
    if code ~= 200 then
        error_print("Webhook request failed. Response: " .. table.concat(response))
    end
    return code, table.concat(response)
end

local linda = lanes.linda()

local function handle_async_request(docker_image, command)
    local result = execute_docker_command(docker_image, command)
    linda:send("async_results", result)
end

local function create_https_server(port)
    local server = assert(socket.bind("0.0.0.0", port))
    local ctx = assert(ssl.newcontext({
        mode = "server",
        protocol = "any",
        key = SERVER_KEY,
        certificate = SERVER_CERT,
        cafile = CA_CERT,
        verify = {"peer", "fail_if_no_peer_cert"},
        options = {"all", "no_sslv2", "no_sslv3", "no_tlsv1"}
    }))
    return server, ctx
end

local function generate_hmac(message, secret)
    return hmac_sha256(secret, message)
end

local function handle_https_request(client, ctx)
    local ssl_client = assert(ssl.wrap(client, ctx))
    local success, err = ssl_client:dohandshake()
    if not success then
        error_print("TLS handshake failed: " .. tostring(err))
        ssl_client:close()
        return
    end

    -- Verify client certificate
    local cert = ssl_client:getpeercertificate()
    if not cert then
        error_print("No client certificate provided")
        ssl_client:close()
        return
    end

    debug_print("Client certificate verified")

    ssl_client:settimeout(15)
    
    local request = ""
    while true do
        local line, err = ssl_client:receive()
        if err then
            error_print("Failed to receive request: " .. err)
            ssl_client:close()
            return
        end
        request = request .. line .. "\r\n"
        if line == "" then break end
    end
    
    debug_print("Received request headers:\n" .. request)
    
    local method, path = request:match("(%u+) (/%S*) HTTP/[%d.]+")
    
    if not method or not path then
        error_print("Invalid request received")
        ssl_client:send("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid Request")
        ssl_client:close()
        return
    end
    
    local content_length = tonumber(request:match("Content%-Length: (%d+)"))
    local body = ""
    if content_length then
        body, err = ssl_client:receive(content_length)
        if err then
            error_print("Failed to receive request body: " .. err)
            ssl_client:close()
            return
        end
    end
    
    debug_print("Received request body: '" .. body .. "'")
    
    if method == "POST" and path == "/thiefd"
-- [Previous part of the script remains unchanged]

local function handle_https_request(client, ctx)
    local ssl_client = assert(ssl.wrap(client, ctx))
    local success, err = ssl_client:dohandshake()
    if not success then
        error_print("TLS handshake failed: " .. tostring(err))
        ssl_client:close()
        return
    end

    -- Verify client certificate
    local cert = ssl_client:getpeercertificate()
    if not cert then
        error_print("No client certificate provided")
        ssl_client:close()
        return
    end

    debug_print("Client certificate verified")

    ssl_client:settimeout(15)
    
    local request = ""
    while true do
        local line, err = ssl_client:receive()
        if err then
            error_print("Failed to receive request: " .. err)
            ssl_client:close()
            return
        end
        request = request .. line .. "\r\n"
        if line == "" then break end
    end
    
    debug_print("Received request headers:\n" .. request)
    
    local method, path = request:match("(%u+) (/%S*) HTTP/[%d.]+")
    
    if not method or not path then
        error_print("Invalid request received")
        ssl_client:send("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid Request")
        ssl_client:close()
        return
    end
    
    local content_length = tonumber(request:match("Content%-Length: (%d+)"))
    local body = ""
    if content_length then
        body, err = ssl_client:receive(content_length)
        if err then
            error_print("Failed to receive request body: " .. err)
            ssl_client:close()
            return
        end
    end
    
    debug_print("Received request body: '" .. body .. "'")
    
    if method == "POST" and path == "/thiefd" then
        debug_print("Processing POST /thiefd request")
        
        -- Verify HMAC
        local hmac_header = request:match("X%-HMAC%-SHA256: (%w+)")
        if not hmac_header then
            debug_print("Bad request: missing HMAC header")
            ssl_client:send("HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\nMissing HMAC authentication")
            ssl_client:close()
            return
        end
        
        local calculated_hmac = generate_hmac(body, HMAC_SECRET)
        if calculated_hmac ~= hmac_header then
            debug_print("Invalid HMAC")
            ssl_client:send("HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\nInvalid HMAC authentication")
            ssl_client:close()
            return
        end
        
        debug_print("HMAC verified successfully")
        
        if not body or body == "" then
            debug_print("Bad request: missing command")
            ssl_client:send("HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nCommand is required")
        else
            local command, webhook_url = body:match("^(.-)\n(.+)$")
            if not command then
                command = body
            end
            command = command:gsub("^%s*(.-)%s*$", "%1")
            local is_async = command:match("^async") ~= nil
            if is_async then
                command = command:gsub("^async%s*", "")
            end
            
            debug_print("Processed command: '" .. command .. "', Async: " .. tostring(is_async) .. ", Webhook: " .. (webhook_url or "None"))
            
            if FORWARD_MODE or is_async then
                ssl_client:send("HTTP/1.1 202 Accepted\r\nContent-Type: text/plain\r\n\r\nRequest accepted for processing")
                ssl_client:close()
                lanes.gen("*", handle_async_request)(DOCKER_IMAGE, command)
                
                local _, result = linda:receive("async_results")
                
                local webhook_to_use = FORWARD_MODE and FORWARD_WEBHOOK_URL or webhook_url
                send_webhook(webhook_to_use, "thiefd command results:\n" .. result)
            else
                local result = execute_docker_command(DOCKER_IMAGE, command)
                ssl_client:send("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" .. result)
            end
        end
    else
        debug_print("Not found: " .. method .. " " .. path)
        ssl_client:send("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nNot Found")
    end
    
    debug_print("Closing client connection")
    ssl_client:close()
end

local function generate_certificates()
    print("Generating TLS certificates...")
    
    -- Prompt for certificate details
    print("Enter the Common Name for the CA (e.g., Your Company Name):")
    local ca_cn = io.read()
    print("Enter the Common Name for the server certificate (e.g., localhost or your domain):")
    local server_cn = io.read()
    print("Enter the Common Name for the client certificate (e.g., ClientName):")
    local client_cn = io.read()
    
    -- Create a directory for certificates
    os.execute("mkdir -p certs")
    
    -- Generate CA key and certificate
    os.execute("openssl genpkey -algorithm RSA -out certs/ca.key")
    os.execute(string.format("openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 1024 -out certs/ca.crt -subj '/CN=%s'", ca_cn))
    
    -- Generate server key and CSR
    os.execute("openssl genpkey -algorithm RSA -out certs/server.key")
    os.execute(string.format("openssl req -new -key certs/server.key -out certs/server.csr -subj '/CN=%s'", server_cn))
    
    -- Sign server certificate with CA
    os.execute("openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt -days 365 -sha256")
    
    -- Generate client key and CSR
    os.execute("openssl genpkey -algorithm RSA -out certs/client.key")
    os.execute(string.format("openssl req -new -key certs/client.key -out certs/client.csr -subj '/CN=%s'", client_cn))
    
    -- Sign client certificate with CA
    os.execute("openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/client.crt -days 365 -sha256")
    
    print("Certificates generated successfully in the 'certs' directory.")
end

-- Main function
local function main()
    print_logo()
    
    if #arg < 1 then
        print("Usage: lua script.lua <port> [--forward <webhook_url>]")
        os.exit(1)
    end
    
    local port = tonumber(arg[1])
    if not port then
        print("Invalid port number")
        os.exit(1)
    end
    
    if arg[2] == "--forward" and arg[3] then
        FORWARD_MODE = true
        FORWARD_WEBHOOK_URL = arg[3]
        print("Running in forward mode. All requests will be sent to: " .. FORWARD_WEBHOOK_URL)
    else
        print("Running in normal mode.")
    end

    print("Do you want to generate new TLS certificates? (y/n)")
    local generate_certs = io.read():lower()
    if generate_certs == "y" then
        generate_certificates()
    else
        print("Using existing certificates. Make sure they are properly configured.")
    end

    print("Enter the Docker image name to use:")
    DOCKER_IMAGE = io.read()
    
    local server, ctx = create_https_server(port)
    debug_print("Server listening on port " .. port .. " (HTTPS with mutual TLS)...")

    while true do
        debug_print("Waiting for new connection...")
        local client, err = server:accept()
        if client then
            debug_print("New connection accepted")
            local ok, err = pcall(handle_https_request, client, ctx)
            if not ok then
                error_print("Error handling request: " .. tostring(err))
            end
        else
            error_print("Failed to accept connection: " .. tostring(err))
        end
    end
end

-- Run the main function
main()
