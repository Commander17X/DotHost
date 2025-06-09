# Dothost - Website Hosting Management System

Dothost is a comprehensive website hosting management system that automates the process of setting up and managing websites on Nginx servers. It provides a user-friendly menu interface for managing websites, SSL certificates, and security configurations.

## Features

- Create and manage multiple websites
- Automatic Nginx configuration
- SSL certificate management with Let's Encrypt
- Built-in security measures
- PHP-FPM support
- Rate limiting
- Security headers
- Logging system

## Prerequisites

- Ubuntu/Debian-based Linux system
- Nginx web server
- PHP-FPM (7.4, 8.0, 8.1, or 8.2)
- Root access

## Installation

1. Clone the repository:
```bash
git clone https://github.com/command17x/dothost.git
cd dothost
```

2. Make the script executable:
```bash
chmod +x dothost.sh
```

3. Run the script as root:
```bash
sudo ./dothost.sh
```

## Usage

The script provides a menu-driven interface with the following options:

1. **Create new website**
   - Enter domain name
   - Select PHP version
   - Automatically configures Nginx
   - Sets up security measures

2. **Enable SSL for website**
   - Installs Certbot if not present
   - Obtains SSL certificate from Let's Encrypt
   - Configures Nginx for HTTPS

3. **List all websites**
   - Shows all configured websites

4. **Delete website**
   - Removes website configuration
   - Deletes website files
   - Removes SSL certificates

## Security Features

- X-Frame-Options header
- X-XSS-Protection header
- X-Content-Type-Options header
- HSTS (HTTP Strict Transport Security)
- Rate limiting
- Hidden file access prevention
- Proper file permissions

## Directory Structure

- `/var/www/` - Website files
- `/etc/nginx/conf.d/` - Nginx configurations
- `/etc/ssl/dothost/` - SSL certificates
- `/var/log/dothost/` - Website logs

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
