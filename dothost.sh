#!/bin/bash

# Dothost - Website Hosting Management System
# Author: Dothost Team
# Version: 1.0

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
NGINX_CONF_DIR="/etc/nginx/conf.d"
WEBSITES_DIR="/var/www"
SSL_DIR="/etc/ssl/dothost"
LOGS_DIR="/var/log/dothost"

# Create necessary directories if they don't exist
mkdir -p "$WEBSITES_DIR" "$SSL_DIR" "$LOGS_DIR"

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Please run as root${NC}"
        exit 1
    fi
}

# Function to create a new website
create_website() {
    echo -e "${YELLOW}Creating new website...${NC}"
    read -p "Enter domain name: " domain
    read -p "Enter PHP version (7.4/8.0/8.1/8.2): " php_version
    
    # Create website directory
    website_dir="$WEBSITES_DIR/$domain"
    mkdir -p "$website_dir"
    
    # Create Nginx configuration
    cat > "$NGINX_CONF_DIR/$domain.conf" << EOF
server {
    listen 80;
    server_name $domain www.$domain;
    root $website_dir;
    index index.php index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Content-Type-Options "nosniff";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=one:10m rate=1r/s;
    limit_req zone=one burst=10 nodelay;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php$php_version-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    # Deny access to hidden files
    location ~ /\. {
        deny all;
    }

    # Logs
    access_log $LOGS_DIR/$domain-access.log;
    error_log $LOGS_DIR/$domain-error.log;
}
EOF

    # Set permissions
    chown -R www-data:www-data "$website_dir"
    chmod -R 755 "$website_dir"
    
    # Test Nginx configuration
    nginx -t
    
    if [ $? -eq 0 ]; then
        systemctl reload nginx
        echo -e "${GREEN}Website $domain has been created successfully!${NC}"
    else
        echo -e "${RED}Error in Nginx configuration${NC}"
        exit 1
    fi
}

# Function to enable SSL for a website
enable_ssl() {
    echo -e "${YELLOW}Enabling SSL for website...${NC}"
    read -p "Enter domain name: " domain
    
    # Install certbot if not installed
    if ! command -v certbot &> /dev/null; then
        apt-get update
        apt-get install -y certbot python3-certbot-nginx
    fi
    
    # Obtain SSL certificate
    certbot --nginx -d $domain -d www.$domain
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}SSL has been enabled for $domain${NC}"
    else
        echo -e "${RED}Error enabling SSL${NC}"
        exit 1
    fi
}

# Function to list all websites
list_websites() {
    echo -e "${YELLOW}List of all websites:${NC}"
    for conf in "$NGINX_CONF_DIR"/*.conf; do
        if [ -f "$conf" ]; then
            domain=$(basename "$conf" .conf)
            echo -e "${GREEN}$domain${NC}"
        fi
    done
}

# Function to delete a website
delete_website() {
    echo -e "${YELLOW}Deleting website...${NC}"
    read -p "Enter domain name to delete: " domain
    
    # Remove Nginx configuration
    rm -f "$NGINX_CONF_DIR/$domain.conf"
    
    # Remove website directory
    rm -rf "$WEBSITES_DIR/$domain"
    
    # Remove SSL certificates if they exist
    certbot delete --cert-name $domain
    
    # Reload Nginx
    systemctl reload nginx
    
    echo -e "${GREEN}Website $domain has been deleted${NC}"
}

# Main menu
show_menu() {
    clear
    echo -e "${YELLOW}=== Dothost Website Management System ===${NC}"
    echo "1. Create new website"
    echo "2. Enable SSL for website"
    echo "3. List all websites"
    echo "4. Delete website"
    echo "5. Exit"
    echo
    read -p "Enter your choice (1-5): " choice
    
    case $choice in
        1) create_website ;;
        2) enable_ssl ;;
        3) list_websites ;;
        4) delete_website ;;
        5) exit 0 ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
    esac
    
    read -p "Press Enter to continue..."
    show_menu
}

# Check if running as root
check_root

# Start the menu
show_menu 