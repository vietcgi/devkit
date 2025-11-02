# Security Role

## Overview

The **Security** role sets up cryptographic and security infrastructure including:

- SSH key generation and configuration
- SSH client hardening
- GPG setup and key management
- Security audit logging
- Authentication best practices

## Purpose

This role establishes secure communication channels (SSH) and authentication mechanisms (GPG) for development, protecting credentials and ensuring secure system administration.

## Requirements

- Ansible 2.9+
- **Core role** (must run first)
- Valid `$HOME` environment variable
- Appropriate privileges for key generation

## Role Variables

### Default Variables (`defaults/main.yml`)

```yaml
enable_ssh_setup: false                 # Enable SSH key generation
enable_gpg_setup: false                 # Enable GPG setup
home_dir: "{{ ansible_user_dir }}"     # User's home directory
```

### Optional Variables

```yaml
ssh_key_type: "ed25519"                # SSH key algorithm (ed25519, rsa, etc.)
ssh_key_bits: 4096                     # RSA key size if using RSA
```

## Tasks Performed

### SSH Key Setup

1. **SSH Directory Creation**
   - Create `~/.ssh` with secure permissions (0700)

2. **Key Generation**
   - Generate ED25519 SSH key pair (modern, secure)
   - Create `~/.ssh/id_ed25519` (private key)
   - Create `~/.ssh/id_ed25519.pub` (public key)
   - Set secure permissions (0600 for private key)

3. **SSH Configuration**
   - Create `~/.ssh/config` with security best practices
   - Configure key-based authentication
   - Disable password authentication
   - Enable agent key caching
   - Set strict host key checking

4. **SSH Agent Integration**
   - Configure key loading on shell startup
   - Integrate with system keychain (macOS)

### GPG Setup

1. **GPG Key Management** (when enabled)
   - List existing GPG keys
   - Create keyring structure
   - Initialize GPG configuration

## Handlers

This role provides 8 handlers:

- `verify ssh key generation` - Check SSH key exists
- `verify ssh config` - Validate SSH configuration
- `set secure ssh key permissions` - Ensure correct permissions
- `set secure ssh config permissions` - Config file permissions
- `restart ssh agent` - Reload SSH agent with new keys
- `notify ssh setup complete` - Completion message
- `verify gpg setup` - Check GPG availability
- `notify security setup complete` - Final notification

## Dependencies

- **core** role (provides system variables)

## Example Playbook

```yaml
# Set up SSH only
- name: Configure security
  hosts: localhost
  vars:
    enable_ssh_setup: true
  roles:
    - core
    - security

# Set up SSH and GPG
- name: Full security configuration
  hosts: localhost
  vars:
    enable_ssh_setup: true
    enable_gpg_setup: true
  roles:
    - core
    - security
```

## SSH Configuration

Default SSH config includes:

```
Host *
  AddKeysToAgent yes
  UseKeychain yes
  IdentityFile ~/.ssh/id_ed25519
  ServerAliveInterval 60
  ServerAliveCountMax 10
  HashKnownHosts yes
  VisualHostKey no
  PasswordAuthentication no
  PubkeyAuthentication yes
  StrictHostKeyChecking accept-new
  UserKnownHostsFile ~/.ssh/known_hosts
  LogLevel VERBOSE
```

## Security Features

| Feature | Benefit |
|---------|---------|
| **ED25519 Keys** | Modern, secure, faster than RSA |
| **Key Agent** | Encrypted key storage, no password typing |
| **Strict Host Checking** | Prevent MITM attacks |
| **No Password Auth** | Require key-based authentication |
| **HashKnownHosts** | Obfuscate known hosts file |
| **Server Alive** | Keep connections alive through firewalls |

## Tags

- `security` - All security tasks
- `ssh` - SSH-specific tasks
- `config` - Configuration files
- `gpg` - GPG tasks
- `keys` - Key generation tasks
- `agent` - SSH agent tasks

## Configuration Files

- **SSH Keys**: `~/.ssh/id_ed25519*`
- **SSH Config**: `~/.ssh/config`
- **Known Hosts**: `~/.ssh/known_hosts`
- **GPG Keys**: `~/.gnupg/`

## Post-Setup Steps

After SSH key generation:

1. **Add Public Key to GitHub/GitLab**

   ```bash
   cat ~/.ssh/id_ed25519.pub
   # Copy output to GitHub Settings → SSH Keys
   ```

2. **Test SSH Connection**

   ```bash
   ssh -T git@github.com
   # Should show: "Hi username! You've successfully authenticated..."
   ```

3. **Configure Git (if not done)**

   ```bash
   git config --global user.signingkey ~/.ssh/id_ed25519
   ```

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| SSH key not found | Not generated | Enable `enable_ssh_setup: true` |
| Permission denied | Wrong key perms | Verify `~/.ssh/id_ed25519` is 0600 |
| Agent not working | Not configured | Check SSH agent is running: `ssh-add -l` |
| Unknown host | Known hosts empty | SSH to host once to accept key |
| Key not added to agent | Shell not sourced | Restart terminal or source shell config |

## Security Best Practices

1. **Never commit private keys** to version control
2. **Back up private keys** in secure location
3. **Use ssh-agent** to avoid typing passphrases
4. **Regularly rotate keys** (annually recommended)
5. **Use unique keys** for different systems
6. **Monitor known_hosts** for unauthorized entries

## See Also

- [SSH Best Practices](https://www.ssh.com/ssh/best-practices)
- [ED25519 vs RSA](https://security.stackexchange.com/questions/90077/ssh-key-ed25519-vs-rsa)
- [GitHub SSH Setup](https://docs.github.com/en/authentication/connecting-to-github-with-ssh)
- [GPG Key Generation](https://docs.github.com/en/authentication/managing-commit-signature-verification)
- Related roles: `core`, `git`
