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
SECURITY_DIR="/etc/dothost/security"

# Create necessary directories if they don't exist
mkdir -p "$WEBSITES_DIR" "$SSL_DIR" "$LOGS_DIR" "$SECURITY_DIR"

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

# Main menu
show_menu() {
    clear
    echo -e "${YELLOW}=== Dothost Website Management System ===${NC}"
    echo "1. Create new website"
    echo "2. Enable SSL for website"
    echo "3. List all websites"
    echo "4. Delete website"
    echo "5. Security Management"
    echo "6. Exit"
    echo
    read -p "Enter your choice (1-6): " choice
    
    case $choice in
        1) create_website ;;
        2) enable_ssl ;;
        3) list_websites ;;
        4) delete_website ;;
        5) show_security_menu ;;
        6) exit 0 ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
    esac
    
    read -p "Press Enter to continue..."
    show_menu
}

# Security menu
show_security_menu() {
    clear
    echo -e "${YELLOW}=== Security Management ===${NC}"
    echo "1. Configure ModSecurity"
    echo "2. Configure fail2ban"
    echo "3. Configure firewall"
    echo "4. Show security status"
    echo "5. Back to main menu"
    echo
    read -p "Enter your choice (1-5): " choice
    
    case $choice in
        1) configure_modsecurity ;;
        2) configure_fail2ban ;;
        3) configure_firewall ;;
        4) show_security_status ;;
        5) return ;;
        *) echo -e "${RED}Invalid choice${NC}" ;;
    esac
    
    read -p "Press Enter to continue..."
    show_security_menu
}

# Check if running as root
check_root

# Start the menu
show_menu 