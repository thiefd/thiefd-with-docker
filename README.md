# Thiefd with Docker

This README provides step-by-step instructions for setting up and running the `thiefd-with-docker.lua` script, which creates a REST API for executing Docker commands with mutual TLS authentication.

## Prerequisites

Before you begin, ensure you have the following installed on your system:

1. **Lua**: Version 5.1 or later
2. **LuaRocks**: The package manager for Lua
3. **OpenSSL**: For generating TLS certificates
4. **Docker**: For running containerized commands

## Step 1: Install Docker

If you don't have Docker installed, follow these steps:

1. Visit the official Docker website: https://docs.docker.com/get-docker/
2. Choose your operating system and follow the installation instructions.
3. After installation, verify Docker is working by running:
   ```
   docker --version
   ```

## Step 2: Install Lua and LuaRocks

Install Lua and LuaRocks using your system's package manager. For example, on Ubuntu:

```bash
sudo apt-get update
sudo apt-get install lua5.3 luarocks
```

## Step 3: Install Lua Dependencies

Install the required Lua libraries using LuaRocks:

```bash
sudo luarocks install luasocket
sudo luarocks install luasec
sudo luarocks install lanes
```

## Step 4: Install OpenSSL

OpenSSL is usually pre-installed on most systems. If it's not, install it using your system's package manager. For example, on Ubuntu:

```bash
sudo apt-get install openssl
```

## Step 5: Prepare the Script

1. Save the `thiefd-with-docker.lua` script to your desired location.
2. Make sure the script has execute permissions:
   ```bash
   chmod +x thiefd-with-docker.lua
   ```

## Step 6: Run the Script

Run the script using the following command:

```bash
lua thiefd-with-docker.lua <port> [--forward <webhook_url>]
```

Replace `<port>` with the desired port number for the HTTPS server. The `--forward` option is optional and can be used to specify a webhook URL for forwarding results.

## Step 7: Follow the Prompts

1. The script will ask if you want to generate new TLS certificates. Enter 'y' if you need to create new certificates, or 'n' if you already have certificates.

2. If generating new certificates, you'll be prompted to enter:
   - Common Name for the CA
   - Common Name for the server certificate
   - Common Name for the client certificate

3. Enter the Docker image name you want to use for executing commands.

## Step 8: Use the API

Once the server is running, you can send HTTPS POST requests to `https://your-server:port/thiefd` with the following:

- A valid client certificate for authentication
- The command to execute in the request body

Example using curl:

```bash
curl -X POST \
     --cert client.crt \
     --key client.key \
     --cacert ca.crt \
     -d "your_docker_command_here" \
     https://your-server:port/thiefd
```
