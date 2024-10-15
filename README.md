# Thiefd, Functions-as-a-Service in Lua

This README provides step-by-step instructions for setting up and running THIEFD, and open-source function-as-a-service framework written in Lua.

## Prerequisites

- Ubuntu-based system (for apt-get commands)
- Sudo access
- Docker installed and configured

## Installation Steps

1. Install Lua and required system dependencies:

   ```
   sudo apt-get update
   sudo apt-get install -y lua5.3 liblua5.3-dev luarocks build-essential libssl-dev
   ```

2. Install Lua dependencies using LuaRocks:

   ```
   sudo luarocks install luasocket
   sudo luarocks install luasec
   sudo luarocks install lanes
   sudo luarocks install luafilesystem
   ```

3. Install Certbot for SSL certificate management:

   ```
   sudo apt-get install -y certbot
   ```

4. Set up the required environment variables:

   ```
   export THIEFD_FORWARD_MODE=false
   export THIEFD_DOCKER_IMAGE="your-docker-image-name"
   export THIEFD_API_USERNAME="your-api-username"
   export THIEFD_API_PASSWORD="your-api-password"
   export THIEFD_SERVER_PORT=443
   export THIEFD_DOMAIN="your-domain.com"
   export THIEFD_EMAIL="your-email@example.com"
   ```

   Replace the placeholder values with your actual configuration.

   Optional: If you want to use forward mode, also set:
   ```
   export THIEFD_FORWARD_MODE=true
   export THIEFD_FORWARD_WEBHOOK_URL="https://your-webhook-url.com"
   ```

5. Save the Lua script to a file named `thiefd.lua`.

## Running the Script

1. Make sure you have root privileges to bind to port 443:

   ```
   sudo -E lua thiefd.lua
   ```

   The `-E` flag ensures that your environment variables are passed to the sudo environment.

2. The script will automatically attempt to obtain or renew a Let's Encrypt SSL certificate for your domain.

3. Once running, the server will listen for HTTPS requests on the specified port (default 443).

## Usage

Send POST requests to `https://your-domain.com/thiefd` with the following:

- Basic Authentication using the API username and password
- Request body containing the Docker command to execute

Example using curl:

```
curl -X POST -u "your-api-username:your-api-password" \
     -d "your docker command here" \
     https://your-domain.com/thiefd
```

## Security Considerations

- Ensure your server is properly secured, as this script allows remote execution of Docker commands.
- Use strong, unique credentials for the API username and password.
- Regularly update and patch your system and all dependencies.
- Monitor logs and access to the server.

## Troubleshooting

- If you encounter permission issues, ensure you're running the script with appropriate privileges.
- Check that all required environment variables are correctly set.
- Verify that your domain's DNS is properly configured to point to your server's IP address.
- Ensure that port 443 is open and accessible from the internet.

For any issues or questions, please contact the script maintainer.
