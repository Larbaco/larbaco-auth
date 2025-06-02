# Larbaco Auth – Secure Server Authentication

![Banner](https://placehold.co/50x50?text=Larbaco+Auth+logo)

**A comprehensive authentication system for Minecraft 1.21.1 servers**  
*NeoForge Mod | GPL-3.0 Licensed | Java 21+ Required*

[![CurseForge](https://cf.way2much.no/shortcuts/curseforge_button.svg)](https://www.curseforge.com/minecraft/mc-mods/larbaco-auth)  
[![Discord](https://img.shields.io/discord/your-server-id?logo=discord)](https://discord.gg/your-invite-link) <!-- Replace with real values -->

---

## 🛡️ Current Features

### **🔐 Advanced Security**
- **AES-256 Encryption** for session tokens
- **BCrypt Password Hashing** with salt rounds
- **Brute-force Protection** (configurable failed attempts limit)
- **Session Management** with automatic expiration (30 seconds)
- **Account Lockout** system with configurable duration

### **⚡ Performance & Monitoring**
- **Real-time System Monitoring** with health checks
- **Comprehensive Logging** with automatic rotation
- **Security Alerts** for suspicious activity
- **Performance Metrics** tracking
- **Database Optimization** tools

### **🗃️ Data Management**
- **JSON-based Storage** (SQLite planned for v1.1)
- **Automatic Backups** with ZIP compression
- **Database Integrity Verification**
- **Player Game Mode Persistence**
- **Thread-safe Operations**

### **🌍 Multi-language Support**
- **English (en_us)** and **Portuguese (pt_br)** built-in
- **Automatic Language Detection** based on system locale
- **Extensible Translation System**

### **👤 Player Experience**
- **Secure Token-based Authentication** (no passwords in chat)
- **Movement Restriction** for unauthenticated players
- **Visual Effects** (blindness) during authentication
- **Clickable Authentication Messages**

---

## ⚙️ Installation

1. Install **NeoForge 1.21.1** (21.1.77+)
2. Download the latest release
3. Place the `.jar` file in the `mods/` folder
4. Start the server to generate the default configuration

### 🛠 Configuration

The mod auto-generates `config/larbaco_auth-common.toml`:

```toml
[security]
maxLoginAttempts = 3
sessionDuration = 30
requireMixedCase = true
requireSpecialChar = true
lockoutDuration = 15
passwordMinLength = 6
requireNumbers = false

[performance]
maxConcurrentSessions = 100
databasePoolSize = 5

[monitoring]
enableDetailedLogging = true
logRetentionDays = 30
enableMonitoring = false
healthCheckInterval = 5
```

---

## 📚 Usage

### **Player Commands**

```bash
# Registration Process
/register                         # Show password requirements
/register <password>              # Validate password and generate token
/auth <token>                     # Complete registration with token

# Login Process  
/login                           # Prompt for password
/login <password>                # Validate password and generate token
/auth <token>                    # Complete login with token

# Password Management
/changepassword                  # Prompt for new password
/changepassword <new_password>   # Validate password and generate token
/auth <token>                    # Complete password change with token

# Session Management
/disconnect                      # Disconnect and reset session
/logout                         # Alias for /disconnect
```

### **Administrative Commands**

```bash
# System Management
/authman reload              # Reload configuration
/authman cleanup             # Clean expired sessions
/authman stats               # Show system statistics
/authman status              # Show system health

# Logging & Monitoring  
/authman logs [player] [lines]    # View authentication logs
/authman monitor start/stop       # Control real-time monitoring
/authman monitor report           # Generate detailed report

# Database Management
/authman database backup          # Create database backup
/authman database optimize        # Optimize database
/authman database verify          # Check database integrity

# Information
/authman info               # Show system information
/authman help               # Show command help
```

---

## 🔑 Permissions

| Permission Level | Required For | Description |
|------------------|--------------|-------------|
| **Level 0** (All Players) | `/register`, `/login`, `/auth` | Basic authentication |
| **Level 3** (Operators) | `/authman` commands | Administrative access |

---

## 📊 Monitoring Features

### **Real-time Statistics**
- Player registration/authentication counts
- Session creation/expiration tracking
- Database operation monitoring
- Memory usage and performance metrics

### **Security Monitoring**
- Failed login attempt detection
- Rapid session creation alerts
- Account lockout tracking
- Administrative action logging

### **Health Checks**
- Component status monitoring
- Performance threshold alerts
- Configuration validation
- Database integrity checks

---

## 🗂️ File Structure

```
config/larbaco_auth/
├── larbaco_auth-common.toml     # Main configuration
├── players.json                 # Player credentials (encrypted)
├── game_modes.json             # Player game mode persistence
├── backups/                    # Automatic database backups
│   └── larbaco_auth_backup_*.zip
├── logs/                       # Authentication logs
│   ├── auth.log               # Current log file
│   └── auth.log.2025-01-*     # Archived logs
└── reports/                    # Monitoring reports
    └── system_report_*.json
```

---

## 🔧 API for Developers

### **Check Authentication Status**
```java
boolean isAuthenticated = LarbacoAuthMain.isPlayerAuthenticated(player.getUUID());
```

### **Listen for Authentication Events**
```java
@SubscribeEvent
public void onPlayerLogin(PlayerEvent.PlayerLoggedInEvent event) {
    // Handle authenticated player login
}
```

---

## ❓ FAQ

**Q: How do I reset a player's password?**  
A: Use `/authman database backup` first, then manually edit `players.json` or wait for the reset feature in v1.1.

**Q: Can I migrate from other auth mods?**  
A: Currently no automatic migration. Manual player re-registration required.

**Q: What happens during server restart?**  
A: All data persists. Players need to re-authenticate after restart.

**Q: How secure are the stored passwords?**  
A: Passwords are hashed with BCrypt (12 rounds) and never stored in plain text.

**Q: Can I disable the monitoring features?**  
A: Yes, set `enableMonitoring = false` and `enableDetailedLogging = false` in config.

---

## 🛣️ Roadmap

### **v1.1 - Enhanced Administration (Planned)**
- Player management commands (`/authman unlock <player>`)
- Password reset system
- SQLite database migration
- Web-based admin panel

### **v1.2 - User Experience (Planned)**
- GUI-based authentication
- 2FA support (optional)
- Email verification system
- Custom authentication sounds/effects

### **v1.3 - Advanced Features (Planned)**
- MySQL database support
- API for third-party integration
- Advanced security policies
- Rate limiting and DDoS protection

---

## 🐛 Known Issues

- Session tokens expire quickly (30 seconds) - increase in config if needed
- No GUI yet - command-line only authentication
- Limited to JSON storage - SQLite coming in v1.1

---

## 📜 License

Licensed under the **GNU General Public License v3.0**.

You **must**:
- Disclose source code for any modifications
- Retain original copyright notice
- Include a copy of this license with distributions

---

## 🛠 Support

- **Issue Tracker**: Use [GitHub Issues](https://github.com/your-repo/issues)
- **Community Help**: Join our [Discord Server](https://discord.gg/your-invite-link)
- **Documentation**: Check our [Wiki](https://github.com/your-repo/wiki)

### **Before Reporting Issues**
1. Check `/authman status` for component health
2. Review `config/larbaco_auth/logs/auth.log`
3. Test with `/authman database verify`
4. Include log files and configuration in reports

---

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](CONTRIBUTING.md) for details.

### **Development Setup**
1. Fork the repository
2. Set up NeoForge 1.21.1 development environment
3. Run tests with `/authman` commands in dev environment
4. Submit pull request with detailed description

---

**Maintained with ❤️ by the Larbaco Team**  
*Not affiliated with Mojang or Microsoft*

**Current Version**: 1.0.0 | **NeoForge**: 1.21.1 | **Last Updated**: January 2025