#!/bin/bash

# Dothost - Website Hosting Management System
# Author: Dothost Team
# Version: 1.2

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
NGINX_CONF_DIR="/etc/nginx/conf.d"
NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"
WEBSITES_DIR="/var/www"
SSL_DIR="/etc/ssl/dothost"
LOGS_DIR="/var/log/dothost"
SECURITY_DIR="/etc/dothost/security"
PHP_VERSIONS=("7.4" "8.0" "8.1" "8.2")

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Please run as root${NC}"
        exit 1
    fi
}

# Function to install dependencies
install_dependencies() {
    echo -e "${YELLOW}Installing system dependencies...${NC}"
    
    # Update package lists
    apt-get update
    
    # Install required packages
    apt-get install -y \
        nginx \
        curl \
        wget \
        git \
        unzip \
        certbot \
        python3-certbot-nginx \
        ufw \
        fail2ban \
        libmodsecurity3 \
        libmodsecurity-dev \
        gnupg2 \
        ca-certificates \
        lsb-release \
        software-properties-common
    
    # Install PHP versions
    for version in "${PHP_VERSIONS[@]}"; do
        echo -e "${YELLOW}Installing PHP $version...${NC}"
        add-apt-repository -y ppa:ondrej/php
        apt-get update
        apt-get install -y \
            php$version-fpm \
            php$version-cli \
            php$version-common \
            php$version-curl \
            php$version-mbstring \
            php$version-xml \
            php$version-mysql \
            php$version-gd \
            php$version-zip \
            php$version-bcmath \
            php$version-intl \
            php$version-soap \
            php$version-imap \
            php$version-ldap \
            php$version-redis \
            php$version-memcached
    done
    
    # Install Composer
    if ! command -v composer &> /dev/null; then
        echo -e "${YELLOW}Installing Composer...${NC}"
        curl -sS https://getcomposer.org/installer | php
        mv composer.phar /usr/local/bin/composer
        chmod +x /usr/local/bin/composer
    fi
    
    # Install Node.js and npm
    if ! command -v node &> /dev/null; then
        echo -e "${YELLOW}Installing Node.js and npm...${NC}"
        curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
        apt-get install -y nodejs
    fi
    
    # Create necessary directories
    mkdir -p "$WEBSITES_DIR" "$SSL_DIR" "$LOGS_DIR" "$SECURITY_DIR" "$NGINX_SITES_AVAILABLE" "$NGINX_SITES_ENABLED"
    
    # Configure PHP-FPM
    for version in "${PHP_VERSIONS[@]}"; do
        # Optimize PHP-FPM configuration
        sed -i "s/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/" /etc/php/$version/fpm/php.ini
        sed -i "s/memory_limit = .*/memory_limit = 256M/" /etc/php/$version/fpm/php.ini
        sed -i "s/upload_max_filesize = .*/upload_max_filesize = 64M/" /etc/php/$version/fpm/php.ini
        sed -i "s/post_max_size = .*/post_max_size = 64M/" /etc/php/$version/fpm/php.ini
        sed -i "s/max_execution_time = .*/max_execution_time = 300/" /etc/php/$version/fpm/php.ini
        
        # Optimize PHP-FPM pool configuration
        sed -i "s/pm = dynamic/pm = ondemand/" /etc/php/$version/fpm/pool.d/www.conf
        sed -i "s/pm.max_children = .*/pm.max_children = 50/" /etc/php/$version/fpm/pool.d/www.conf
        sed -i "s/pm.start_servers = .*/pm.start_servers = 5/" /etc/php/$version/fpm/pool.d/www.conf
        sed -i "s/pm.min_spare_servers = .*/pm.min_spare_servers = 5/" /etc/php/$version/fpm/pool.d/www.conf
        sed -i "s/pm.max_spare_servers = .*/pm.max_spare_servers = 35/" /etc/php/$version/fpm/pool.d/www.conf
        
        # Restart PHP-FPM
        systemctl restart php$version-fpm
    done
    
    # Configure Nginx
    cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml+rss application/atom+xml image/svg+xml;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    # Restart Nginx
    systemctl restart nginx
    
    echo -e "${GREEN}All dependencies have been installed and configured${NC}"
}

# Function to check system requirements
check_system() {
    echo -e "${YELLOW}Checking system requirements...${NC}"
    
    # Check if running on a supported system
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
            echo -e "${RED}This script only supports Ubuntu and Debian systems${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Could not determine operating system${NC}"
        exit 1
    fi
    
    # Check available memory
    total_mem=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$total_mem" -lt 1024 ]; then
        echo -e "${YELLOW}Warning: Less than 1GB of RAM detected. Performance may be affected.${NC}"
    fi
    
    # Check available disk space
    free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ "$free_space" -lt 5120 ]; then
        echo -e "${YELLOW}Warning: Less than 5GB of free disk space detected.${NC}"
    fi
    
    echo -e "${GREEN}System requirements check completed${NC}"
}

# Function to setup initial system
setup_system() {
    echo -e "${YELLOW}Setting up initial system configuration...${NC}"
    
    # Set timezone
    timedatectl set-timezone UTC
    
    # Update system
    apt-get update
    apt-get upgrade -y
    
    # Install dependencies
    install_dependencies
    
    # Configure basic firewall rules (only add, don't modify existing)
    if ! ufw status | grep -q "Status: active"; then
        ufw allow ssh
        ufw allow http
        ufw allow https
        ufw --force enable
    fi
    
    # Configure fail2ban
    if ! systemctl is-active --quiet fail2ban; then
        cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
bantime = 86400
EOF
        systemctl restart fail2ban
    fi
    
    echo -e "${GREEN}Initial system setup completed${NC}"
}

# Function to create a new website
create_website() {
    echo -e "${YELLOW}Creating new website...${NC}"
    read -p "Enter domain name: " domain
    read -p "Enter PHP version (7.4/8.0/8.1/8.2): " php_version
    
    # Validate PHP version
    if [[ ! " ${PHP_VERSIONS[@]} " =~ " ${php_version} " ]]; then
        echo -e "${RED}Invalid PHP version. Please choose from: ${PHP_VERSIONS[*]}${NC}"
        return 1
    fi
    
    # Create website directory structure
    website_dir="$WEBSITES_DIR/$domain"
    mkdir -p "$website_dir"/{public,logs,backup}
    
    # Create default index.html
    cat > "$website_dir/public/index.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to $domain</title>
</head>
<body>
    <h1>Welcome to $domain</h1>
    <p>This site is managed by Dothost.</p>
</body>
</html>
EOF

    # Create Nginx configuration
    cat > "$NGINX_SITES_AVAILABLE/$domain.conf" << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $domain www.$domain;
    root $website_dir/public;
    index index.php index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Content-Type-Options "nosniff";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';";

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=one:10m rate=1r/s;
    limit_req zone=one burst=10 nodelay;

    # Gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    gzip_comp_level 6;
    gzip_min_length 1000;

    # Cache control
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php$php_version-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_intercept_errors on;
        fastcgi_buffer_size 128k;
        fastcgi_buffers 4 256k;
        fastcgi_busy_buffers_size 256k;
    }

    # Deny access to hidden files
    location ~ /\. {
        deny all;
    }

    # Logs
    access_log $website_dir/logs/access.log;
    error_log $website_dir/logs/error.log;
}
EOF

    # Enable the site
    ln -sf "$NGINX_SITES_AVAILABLE/$domain.conf" "$NGINX_SITES_ENABLED/$domain.conf"
    
    # Set permissions
    chown -R www-data:www-data "$website_dir"
    chmod -R 755 "$website_dir"
    chmod -R 775 "$website_dir/logs"
    
    # Test Nginx configuration
    nginx -t
    
    if [ $? -eq 0 ]; then
        systemctl reload nginx
        echo -e "${GREEN}Website $domain has been created successfully!${NC}"
        echo -e "${YELLOW}Website files are located at: $website_dir${NC}"
        echo -e "${YELLOW}Logs are located at: $website_dir/logs${NC}"
    else
        echo -e "${RED}Error in Nginx configuration${NC}"
        rm -f "$NGINX_SITES_ENABLED/$domain.conf"
        return 1
    fi
}

# Function to enable SSL for a website
enable_ssl() {
    echo -e "${YELLOW}Enabling SSL for website...${NC}"
    read -p "Enter domain name: " domain
    
    if [ ! -f "$NGINX_SITES_AVAILABLE/$domain.conf" ]; then
        echo -e "${RED}Website configuration not found${NC}"
        return 1
    fi
    
    # Install certbot if not installed
    if ! command -v certbot &> /dev/null; then
        apt-get update
        apt-get install -y certbot python3-certbot-nginx
    fi
    
    # Obtain SSL certificate
    certbot --nginx -d $domain -d www.$domain
    
    if [ $? -eq 0 ]; then
        # Add SSL configuration to the site
        sed -i '/listen 80;/a \    listen 443 ssl http2;\n    listen [::]:443 ssl http2;' "$NGINX_SITES_AVAILABLE/$domain.conf"
        
        # Test and reload Nginx
        nginx -t && systemctl reload nginx
        echo -e "${GREEN}SSL has been enabled for $domain${NC}"
    else
        echo -e "${RED}Error enabling SSL${NC}"
        return 1
    fi
}

# Function to list all websites
list_websites() {
    echo -e "${YELLOW}List of all websites:${NC}"
    echo -e "${GREEN}Domain\t\tStatus\t\tSSL\t\tPHP Version${NC}"
    echo "------------------------------------------------------------"
    
    for conf in "$NGINX_SITES_AVAILABLE"/*.conf; do
        if [ -f "$conf" ]; then
            domain=$(basename "$conf" .conf)
            status="Enabled"
            ssl="No"
            php_version="Unknown"
            
            # Check if site is enabled
            if [ ! -L "$NGINX_SITES_ENABLED/$domain.conf" ]; then
                status="Disabled"
            fi
            
            # Check SSL
            if grep -q "listen 443" "$conf"; then
                ssl="Yes"
            fi
            
            # Get PHP version
            php_version=$(grep -o "php[0-9]\.[0-9]" "$conf" | head -n1 | cut -d'/' -f4)
            
            echo -e "$domain\t$status\t$ssl\t$php_version"
        fi
    done
}

# Function to manage website
manage_website() {
    echo -e "${YELLOW}Website Management${NC}"
    read -p "Enter domain name: " domain
    
    if [ ! -f "$NGINX_SITES_AVAILABLE/$domain.conf" ]; then
        echo -e "${RED}Website not found${NC}"
        return 1
    fi
    
    while true; do
        clear
        echo -e "${YELLOW}=== Managing $domain ===${NC}"
        echo "1. Enable/Disable website"
        echo "2. Enable SSL"
        echo "3. View logs"
        echo "4. Backup website"
        echo "5. Restore website"
        echo "6. Return to main menu"
        echo
        read -p "Enter your choice (1-6): " choice
        
        case $choice in
            1)
                if [ -L "$NGINX_SITES_ENABLED/$domain.conf" ]; then
                    rm "$NGINX_SITES_ENABLED/$domain.conf"
                    echo -e "${GREEN}Website disabled${NC}"
                else
                    ln -sf "$NGINX_SITES_AVAILABLE/$domain.conf" "$NGINX_SITES_ENABLED/$domain.conf"
                    echo -e "${GREEN}Website enabled${NC}"
                fi
                systemctl reload nginx
                ;;
            2) enable_ssl ;;
            3)
                echo -e "${YELLOW}Access Log:${NC}"
                tail -n 20 "$WEBSITES_DIR/$domain/logs/access.log"
                echo -e "\n${YELLOW}Error Log:${NC}"
                tail -n 20 "$WEBSITES_DIR/$domain/logs/error.log"
                ;;
            4)
                backup_dir="$WEBSITES_DIR/$domain/backup"
                backup_file="$backup_dir/backup_$(date +%Y%m%d_%H%M%S).tar.gz"
                tar -czf "$backup_file" -C "$WEBSITES_DIR" "$domain"
                echo -e "${GREEN}Backup created: $backup_file${NC}"
                ;;
            5)
                backup_dir="$WEBSITES_DIR/$domain/backup"
                echo -e "${YELLOW}Available backups:${NC}"
                ls -1 "$backup_dir"/*.tar.gz 2>/dev/null
                read -p "Enter backup filename to restore: " backup_file
                if [ -f "$backup_dir/$backup_file" ]; then
                    tar -xzf "$backup_dir/$backup_file" -C "$WEBSITES_DIR"
                    echo -e "${GREEN}Backup restored${NC}"
                else
                    echo -e "${RED}Backup file not found${NC}"
                fi
                ;;
            6) return ;;
            *) echo -e "${RED}Invalid choice${NC}" ;;
        esac
        
        read -p "Press Enter to continue..."
    done
}

# Function to delete a website
delete_website() {
    echo -e "${YELLOW}Deleting website...${NC}"
    read -p "Enter domain name to delete: " domain
    
    # Confirm deletion
    read -p "Are you sure you want to delete $domain? (y/N): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        return
    fi
    
    # Remove Nginx configuration
    rm -f "$NGINX_SITES_AVAILABLE/$domain.conf"
    rm -f "$NGINX_SITES_ENABLED/$domain.conf"
    
    # Remove website directory
    rm -rf "$WEBSITES_DIR/$domain"
    
    # Remove SSL certificates if they exist
    certbot delete --cert-name $domain
    
    # Reload Nginx
    systemctl reload nginx
    
    echo -e "${GREEN}Website $domain has been deleted${NC}"
}

# Function to configure ModSecurity
configure_modsecurity() {
    echo -e "${YELLOW}Configuring ModSecurity...${NC}"
    
    # Install ModSecurity if not installed
    if ! dpkg -l | grep -q libmodsecurity3; then
        apt-get update
        apt-get install -y libmodsecurity3 libmodsecurity-dev
    fi
    
    # Create ModSecurity configuration
    cat > "$SECURITY_DIR/modsecurity.conf" << EOF
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "text/xml" \
     "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule REQUEST_HEADERS:Content-Type "application/json" \
     "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQUEST_HEADERS:Content-Type "application/x-www-form-urlencoded" \
     "id:'200002',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
EOF

    # Add ModSecurity to Nginx configuration
    cat > "$NGINX_CONF_DIR/modsecurity.conf" << EOF
modsecurity on;
modsecurity_rules_file $SECURITY_DIR/modsecurity.conf;
EOF

    # Reload Nginx
    systemctl reload nginx
    echo -e "${GREEN}ModSecurity has been configured${NC}"
}

# Function to configure fail2ban
configure_fail2ban() {
    echo -e "${YELLOW}Configuring fail2ban...${NC}"
    
    # Install fail2ban if not installed
    if ! command -v fail2ban-server &> /dev/null; then
        apt-get update
        apt-get install -y fail2ban
    fi
    
    # Create fail2ban configuration
    cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3
bantime = 3600

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
bantime = 86400
EOF

    # Restart fail2ban
    systemctl restart fail2ban
    echo -e "${GREEN}fail2ban has been configured${NC}"
}

# Function to configure firewall
configure_firewall() {
    echo -e "${YELLOW}Configuring firewall...${NC}"
    
    # Install ufw if not installed
    if ! command -v ufw &> /dev/null; then
        apt-get update
        apt-get install -y ufw
    fi
    
    # Configure basic firewall rules
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow http
    ufw allow https
    
    # Enable firewall
    ufw --force enable
    
    echo -e "${GREEN}Firewall has been configured${NC}"
}

# Function to show security status
show_security_status() {
    echo -e "${YELLOW}Security Status:${NC}"
    
    # Check ModSecurity
    if dpkg -l | grep -q libmodsecurity3; then
        echo -e "${GREEN}✓ ModSecurity is installed${NC}"
    else
        echo -e "${RED}✗ ModSecurity is not installed${NC}"
    fi
    
    # Check fail2ban
    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}✓ fail2ban is running${NC}"
    else
        echo -e "${RED}✗ fail2ban is not running${NC}"
    fi
    
    # Check firewall
    if ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}✓ Firewall is active${NC}"
    else
        echo -e "${RED}✗ Firewall is not active${NC}"
    fi
}

# Function to manage security headers
manage_security_headers() {
    echo -e "${YELLOW}Security Headers Management${NC}"
    read -p "Enter domain name: " domain
    
    if [ ! -f "$NGINX_SITES_AVAILABLE/$domain.conf" ]; then
        echo -e "${RED}Website not found${NC}"
        return 1
    fi
    
    while true; do
        clear
        echo -e "${YELLOW}=== Managing Security Headers for $domain ===${NC}"
        echo "1. Add/Update Security Headers"
        echo "2. Remove Security Headers"
        echo "3. View Current Security Headers"
        echo "4. Return to Security Menu"
        echo
        read -p "Enter your choice (1-4): " choice
        
        case $choice in
            1)
                # Add/Update security headers
                sed -i '/# Security headers/d' "$NGINX_SITES_AVAILABLE/$domain.conf"
                sed -i '/add_header X-Frame-Options/d' "$NGINX_SITES_AVAILABLE/$domain.conf"
                sed -i '/add_header X-XSS-Protection/d' "$NGINX_SITES_AVAILABLE/$domain.conf"
                sed -i '/add_header X-Content-Type-Options/d' "$NGINX_SITES_AVAILABLE/$domain.conf"
                sed -i '/add_header Strict-Transport-Security/d' "$NGINX_SITES_AVAILABLE/$domain.conf"
                sed -i '/add_header Content-Security-Policy/d' "$NGINX_SITES_AVAILABLE/$domain.conf"
                
                # Add new security headers
                sed -i '/server_name/a \    # Security headers\n    add_header X-Frame-Options "SAMEORIGIN";\n    add_header X-XSS-Protection "1; mode=block";\n    add_header X-Content-Type-Options "nosniff";\n    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n    add_header Content-Security-Policy "default-src '\''self'\''; script-src '\''self'\'' '\''unsafe-inline'\'' '\''unsafe-eval'\''; style-src '\''self'\'' '\''unsafe-inline'\'';";' "$NGINX_SITES_AVAILABLE/$domain.conf"
                
                # Test and reload Nginx
                nginx -t && systemctl reload nginx
                echo -e "${GREEN}Security headers have been updated${NC}"
                ;;
            2)
                # Remove security headers
                sed -i '/# Security headers/d' "$NGINX_SITES_AVAILABLE/$domain.conf"
                sed -i '/add_header X-Frame-Options/d' "$NGINX_SITES_AVAILABLE/$domain.conf"
                sed -i '/add_header X-XSS-Protection/d' "$NGINX_SITES_AVAILABLE/$domain.conf"
                sed -i '/add_header X-Content-Type-Options/d' "$NGINX_SITES_AVAILABLE/$domain.conf"
                sed -i '/add_header Strict-Transport-Security/d' "$NGINX_SITES_AVAILABLE/$domain.conf"
                sed -i '/add_header Content-Security-Policy/d' "$NGINX_SITES_AVAILABLE/$domain.conf"
                
                # Test and reload Nginx
                nginx -t && systemctl reload nginx
                echo -e "${GREEN}Security headers have been removed${NC}"
                ;;
            3)
                # View current security headers
                echo -e "${YELLOW}Current Security Headers:${NC}"
                grep -A 5 "# Security headers" "$NGINX_SITES_AVAILABLE/$domain.conf"
                ;;
            4) return ;;
            *) echo -e "${RED}Invalid choice${NC}" ;;
        esac
        
        read -p "Press Enter to continue..."
    done
}

# Security menu
show_security_menu() {
    clear
    echo -e "${YELLOW}=== Security Management ===${NC}"
    echo "1. Configure ModSecurity"
    echo "2. Configure fail2ban"
    echo "3. Configure firewall"
    echo "4. Manage Security Headers"
    echo "5. Show security status"
    echo "6. Back to main menu"
    echo
    read -p "Enter your choice (1-6): " choice
    
    case $choice in
        1) configure_modsecurity ;;
        2) configure_fail2ban ;;
        3) configure_firewall ;;
        4) manage_security_headers ;;
        5) show_security_status ;;
        6) return ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
    esac
    
    read -p "Press Enter to continue..."
    show_security_menu
}

# Main menu
show_menu() {
    clear
    echo -e "${YELLOW}=== Dothost Website Management System ===${NC}"
    echo "1. Setup System (First Time)"
    echo "2. Create new website"
    echo "3. Manage website"
    echo "4. List all websites"
    echo "5. Delete website"
    echo "6. Security Management"
    echo "7. Exit"
    echo
    read -p "Enter your choice (1-7): " choice
    
    case $choice in
        1) 
            check_system
            setup_system
            ;;
        2) create_website ;;
        3) manage_website ;;
        4) list_websites ;;
        5) delete_website ;;
        6) show_security_menu ;;
        7) exit 0 ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
    esac
    
    read -p "Press Enter to continue..."
    show_menu
}

# Check if running as root
check_root

# Start the menu
show_menu 