#!/bin/sh

# Detect if executed as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Logger
LOG_FILE="./setup.log"
echo "Server setup of $(hostname) started at $(date --rfc-3339=seconds)" > $LOG_FILE

# Check if gum is installed
if command -v gum >/dev/null 2>&1; then
    echo "Using local installation of gum"
    echo "- Using installed gum" >> $LOG_FILE
    GUM="gum"
elif [ -f "./gum" ]; then
    echo "Using gum in local directory"
    echo "- Using local installation of gum" >> $LOG_FILE
    GUM="./gum"
else
    echo "Gum is not installed. Downloading..."
    echo "- Gum is not installed. Downloading..." >> $LOG_FILE
    wget "https://github.com/charmbracelet/gum/releases/download/v0.11.0/gum_0.11.0_Linux_$(arch).tar.gz" -O gum.tar.gz -q
    tar -xzf gum.tar.gz gum >> $LOG_FILE
    rm gum.tar.gz
    echo "Using local installation of gum"
    GUM='./gum'
fi

# Step helpers
STEP_COUNT=13
CURRENT_STEP=1

announce_step() {
    printf "\n" >> $LOG_FILE
    echo "# Step $CURRENT_STEP/$STEP_COUNT: $1" >> $LOG_FILE
    printf "\n"
    $GUM format -t template "{{ Bold (Foreground \"8\" \"[$CURRENT_STEP/$STEP_COUNT]\") }} {{ Bold (Foreground \"14\" \"$1\") }}"
    printf "\n"
    CURRENT_STEP=$((CURRENT_STEP+1))
}

announce_skip() {
    echo "Skipping $1" >> $LOG_FILE
    $GUM format -t template "{{ Foreground \"248\" \"Skipping $1\" }}"
    printf "\n"
}

# Check for updates
announce_step "Checking for updates"

if $GUM confirm "Check for updates?"; then
    echo "- Updating repositories" >> $LOG_FILE
    $GUM spin --title "Updating repositories" --show-output -- apt update >> $LOG_FILE
    echo "Repositories updated"
    echo "- Upgrading packages" >> $LOG_FILE
    echo "Upgrading packages..."
    apt upgrade -y
    echo "Packages upgraded"
else
    announce_skip "packages updates"
fi

# Automatic updates
announce_step "Setting up automatic updates"

if $GUM confirm "Set up automatic updates?"; then
    echo "- Installing unattended-upgrades" >> $LOG_FILE

    $GUM spin --title "Installing unattended-upgrades" --show-output -- apt install unattended-upgrades -y >> $LOG_FILE
    echo "Installed unattended-upgrades"

    dpkg-reconfigure --priority=low unattended-upgrades
    echo "Automatic updates enabled"

    sed -i 's/\/\/\t"${distro_id}:${distro_codename}-updates";/      "${distro_id}:${distro_codename}-updates";/g' /etc/apt/apt.conf.d/50unattended-upgrades
    sed -i 's/\/\/Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";/Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";/g' /etc/apt/apt.conf.d/50unattended-upgrades
    sed -i 's/\/\/Unattended-Upgrade::Remove-Unused-Dependencies "false";/Unattended-Upgrade::Remove-Unused-Dependencies "true";/g' /etc/apt/apt.conf.d/50unattended-upgrades
    sed -i 's/\/\/Unattended-Upgrade::Automatic-Reboot "false";/Unattended-Upgrade::Automatic-Reboot "false";/g' /etc/apt/apt.conf.d/50unattended-upgrades
    echo "unattended-upgrades configured"

    echo "APT::Periodic::Update-Package-Lists \"1\";" > /etc/apt/apt.conf.d/20auto-upgrades
    echo "APT::Periodic::Unattended-Upgrade \"1\";" >> /etc/apt/apt.conf.d/20auto-upgrades
    echo "APT::Periodic::Download-Upgradeable-Packages \"1\";" >> /etc/apt/apt.conf.d/20auto-upgrades
    echo "APT::Periodic::AutocleanInterval \"7\";" >> /etc/apt/apt.conf.d/20auto-upgrades
    echo "apt configured"

    echo "- Unattended Upgrades dry run" >> $LOG_FILE
    $GUM spin --title "Unattended-upgrades dry run" --show-output -- unattended-upgrades --dry-run --debug >> $LOG_FILE

    echo "Enabled automatic updates for security updates"
else
    announce_skip "automatic updates setup"
fi

# Add swap
announce_step "Adding swap"

if $GUM confirm "Add swap?"; then
    SWAP_SIZE=$($GUM input --prompt "Swap size: " --placeholder "1G")

    echo "- Adding swap of $SWAP_SIZE..." >> $LOG_FILE
    $GUM spin --title "Adding swap" --show-output -- fallocate -l "$SWAP_SIZE" /swapfile >> $LOG_FILE
    $GUM spin --title "Adding swap" --show-output -- chmod 600 /swapfile >> $LOG_FILE
    $GUM spin --title "Adding swap" --show-output -- mkswap /swapfile >> $LOG_FILE
    $GUM spin --title "Adding swap" --show-output -- swapon /swapfile >> $LOG_FILE
    echo "/swapfile swap swap defaults 0 0" >> /etc/fstab
    echo "Swap of $SWAP_SIZE added"
else
    announce_skip "swap creation"
fi

# Install fail2ban
announce_step "Installing fail2ban"

if $GUM confirm "Install fail2ban?"; then
    echo "- Installing fail2ban" >> $LOG_FILE
    $GUM spin --title "Installing fail2ban" --show-output -- apt install fail2ban -y >> $LOG_FILE
    echo "Installed fail2ban"

    echo "- Configuring fail2ban" >> $LOG_FILE
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sed -i 's/bantime  = 10m/bantime  = 1h/g' /etc/fail2ban/jail.local
    sed -i 's/findtime  = 10m/findtime  = 1h/g' /etc/fail2ban/jail.local
    sed -i 's/maxretry = 5/maxretry = 3/g' /etc/fail2ban/jail.local
    echo "fail2ban configured"

    echo "- Enabling fail2ban" >> $LOG_FILE
    $GUM spin --title "Enabling fail2ban" --show-output -- systemctl enable fail2ban >> $LOG_FILE
    $GUM spin --title "Enabling fail2ban" --show-output -- systemctl start fail2ban >> $LOG_FILE

    echo "fail2ban enabled"
else
    announce_skip "fail2ban installation and configuration"
fi

# Create user
announce_step "Creating user"

if $GUM confirm "Create new user?"; then
    USERNAME=$($GUM input --prompt "Username: ")
    echo "Username: $USERNAME"
    PASSWORD=$($GUM input --password --prompt "Password: ")
    echo "Password: ***"

    echo "- Creating user $USERNAME" >> $LOG_FILE
    $GUM spin --title "Creating user" --show-output -- useradd -m -s /bin/bash "$USERNAME" >> $LOG_FILE
    echo "$USERNAME:$PASSWORD" | chpasswd
    $GUM spin --title "Creating user" --show-output -- usermod -aG sudo "$USERNAME" >> $LOG_FILE

    echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

    echo "User $USERNAME created"
    USER_HOME="/home/$USERNAME"
else
    announce_skip "user creation"
    USER_HOME="/root"
fi

# SSH keys and config
announce_step "Setting up SSH"

if $GUM confirm "Set up SSH?"; then
    # Create authorized_keys if it doesn't exist
    if [ ! -f "$USER_HOME/.ssh/authorized_keys" ]; then
        mkdir -p "$USER_HOME/.ssh"
        touch "$USER_HOME/.ssh/authorized_keys"
    fi

    if $GUM confirm "SSH method" --affirmative "Generate key" --negative "Enter public key"; then
        KEY_NAME=$($GUM input --prompt "SSH Key name: ")
        echo "- Generating SSH keys" >> $LOG_FILE
        $GUM spin --title "Generating SSH keys" --show-output -- ssh-keygen -t ed25519 -f "$USER_HOME/.ssh/$KEY_NAME" -q -N "" >> $LOG_FILE
        cat "$USER_HOME/.ssh/$KEY_NAME.pub" >> "$USER_HOME/.ssh/authorized_keys"
    else
        echo "- Entering public key" >> $LOG_FILE
        PUBLIC_KEY=$($GUM write --width 0 --height 5 --char-limit 0 --header "Public key (ctrl+D to validate): " --header.foreground "7")
        echo "$PUBLIC_KEY" >> "$USER_HOME/.ssh/authorized_keys"

    fi
    echo "SSH keys configured"

    echo "- Configuring SSH" >> $LOG_FILE
    sed -i 's/#Port 22/Port 22/g' /etc/ssh/sshd_config
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
    sed -i 's/#AuthorizedKeysFile/AuthorizedKeysFile/g' /etc/ssh/sshd_config
    echo "SSH configured"

    if $GUM confirm "Restart SSH service?"; then
        echo "- Restarting SSH service" >> $LOG_FILE
        $GUM spin --title "Restarting SSH service" --show-output -- systemctl restart ssh >> $LOG_FILE
        echo "SSH service restarted"
    fi

else
    announce_skip "SSH configuration"
fi

# Configure firewall
announce_step "Configuring firewall"

if $GUM confirm "Configure firewall?"; then
    echo "- Installing ufw" >> $LOG_FILE
    $GUM spin --title "Installing ufw" --show-output -- apt install ufw -y >> $LOG_FILE
    echo "Installed ufw"

    echo "- Configuring ufw" >> $LOG_FILE
    $GUM spin --title "Configuring ufw" --show-output -- ufw default deny incoming >> $LOG_FILE
    $GUM spin --title "Configuring ufw" --show-output -- ufw default allow outgoing >> $LOG_FILE
    $GUM spin --title "Configuring ufw" --show-output -- ufw limit ssh >> $LOG_FILE
    $GUM spin --title "Configuring ufw" --show-output -- ufw allow http >> $LOG_FILE
    $GUM spin --title "Configuring ufw" --show-output -- ufw allow https >> $LOG_FILE
    $GUM spin --title "Configuring ufw" --show-output -- ufw --force enable >> $LOG_FILE

    echo "Firewall configured"
else
    announce_skip "firewall configuration"
fi

# Install gotop
announce_step "Installing gotop"

if $GUM confirm "Install gotop?"; then
    echo "- Installing gotop" >> $LOG_FILE
    $GUM spin --title "Downloading archive" --show-output -- wget https://github.com/xxxserxxx/gotop/releases/download/v4.2.0/gotop_v4.2.0_linux_amd64.deb -O gotop.deb >> $LOG_FILE
    $GUM spin --title "Installing gotop" --show-output -- dpkg -i gotop.deb >> $LOG_FILE
    rm gotop.deb
    echo "Installed gotop"
else
    announce_skip "gotop installation"
fi

# Install micro
announce_step "Installing micro"

if $GUM confirm "Install micro?"; then
    echo "- Installing micro" >> $LOG_FILE
    $GUM spin --title "Installing micro" --show-output -- sh -c "$(wget -qO- https://getmic.ro)" >> $LOG_FILE
    mv micro /usr/local/bin
    echo "Installed micro"

    echo "- Configuring micro" >> $LOG_FILE
    mkdir -p "$USER_HOME/.config/micro" >> $LOG_FILE
    echo "{" > "$USER_HOME/.config/micro/settings.json"
    echo "  \"mkparents\": true" >> "$USER_HOME/.config/micro/settings.json"
    echo "}" >> "$USER_HOME/.config/micro/settings.json"
    echo "Configured micro"
else
    announce_skip "micro installation"
fi

# Install docker
announce_step "Installing docker"

if $GUM confirm "Install docker?"; then
    echo "- Installing docker" >> $LOG_FILE
    echo "Installing docker..."
    apt install docker.io -y
    echo "Installed docker"

    echo "- Configuring docker" >> $LOG_FILE
    $GUM spin --title "Configuring docker" --show-output -- usermod -aG docker "$USERNAME" >> $LOG_FILE
    echo "Configured docker"

    echo "- Enabling docker" >> $LOG_FILE
    $GUM spin --title "Enabling docker" --show-output -- systemctl enable docker >> $LOG_FILE
    $GUM spin --title "Enabling docker" --show-output -- systemctl start docker >> $LOG_FILE
    echo "Enabled docker"
else
    announce_skip "docker installation"
fi

# .bashrc aliases
announce_step "Setting up aliases"

if $GUM confirm "Set up aliases?"; then
    echo "- Setting up aliases" >> $LOG_FILE

    # Create .bash_aliases if it doesn't exist
    if [ ! -f "$USER_HOME/.bash_aliases" ]; then
        touch "$USER_HOME/.bash_aliases"
    fi

    ALIASES=$($GUM choose --no-limit NodeJS Docker Utils) # result: one answer per line

    printf '%s\n' "$ALIASES" | while IFS= read -r line
    do
        if [ "$line" = "NodeJS" ]; then
            echo "# NodeJS" >> "$USER_HOME/.bash_aliases"
            echo "alias node='docker run --rm -it --network host -v \`pwd\`:/app -w /app node:alpine '" >> "$USER_HOME/.bash_aliases"
            echo "alias npm='docker run --rm -it --network host -v \`pwd\`:/app -w /app node:alpine npm '" >> "$USER_HOME/.bash_aliases"
            echo "alias npx='docker run --rm -it --network host -v \`pwd\`:/app -w /app node:alpine npx '" >> "$USER_HOME/.bash_aliases"
        fi

        if [ "$line" = "Docker" ]; then
            echo "# Docker" >> "$USER_HOME/.bash_aliases"
            echo "alias dps='docker ps -as --format \"table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.RunningFor}}\t{{.Image}}\t{{.Size}}\"'" >> "$USER_HOME/.bash_aliases"
            echo "alias dc='docker compose'" >> "$USER_HOME/.bash_aliases"
        fi

        if [ "$line" = "Utils" ]; then
            echo "# Utils" >> "$USER_HOME/.bash_aliases"
            echo "alias duwd='du -h --max-depth=1 . | sort -hr'" >> "$USER_HOME/.bash_aliases"
        fi
    done

else
    announce_skip "aliases"
fi

# Git credentials
announce_step "Setting up git credentials"

if $GUM confirm "Set up git credentials?"; then
    echo "- Setting up git credentials" >> $LOG_FILE
    GIT_NAME=$($GUM input --prompt "Git name: ")
    GIT_EMAIL=$($GUM input --prompt "Git email: ")
    echo "- Setting up git credentials" >> $LOG_FILE
    git config --global user.name "$GIT_NAME"
    git config --global user.email "$GIT_EMAIL"
    echo "Git credentials configured"
else
    announce_skip "git credentials"
fi

# Custom MOTD
announce_step "Setting up custom MOTD"

if $GUM confirm "Set up custom MOTD?"; then
    echo "- Setting up custom MOTD" >> $LOG_FILE
    chmod -x /etc/update-motd.d/10-help-text >> $LOG_FILE
    chmod -x /etc/update-motd.d/50-motd-news >> $LOG_FILE
    chmod -x /etc/update-motd.d/88-esm-announce >> $LOG_FILE
    chmod -x /etc/update-motd.d/91-contract-ua-esm-status >> $LOG_FILE
else
    announce_skip "custom MOTD"
fi
