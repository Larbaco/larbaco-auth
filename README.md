# Larbaco Auth – Secure Server Authentication

![Banner](https://placehold.co/50x50?text=Larbaco+Auth+logo)

**A security system for Minecraft 1.21.1 servers**  
*NeoForge Mod | GPL-3.0 Licensed | Java 17+ Required*

[![CurseForge](https://cf.way2much.no/shortcuts/curseforge_button.svg)](https://www.curseforge.com/minecraft/mc-mods/larbaco-auth)  
[![Discord](https://img.shields.io/discord/your-server-id?logo=discord)](https://discord.gg/your-invite-link) <!-- Replace with real values -->

---

## 🔒 Planned Features

- **Military-Grade Encryption**  
  AES-256 encryption for all client-server communication.

- **Smart Protection Systems**
    - Brute-force prevention (limit of 3 failed attempts)
    - IP address verification
    - Configurable session timeout

- **Flexible Storage Options**
    - SQLite (default) and MySQL support
    - Encrypted credential storage

- **Modern, Customizable Interface**
    - Login GUI with theming support
    - Multi-language compatibility
    - Admin override system

---

## ⚙️ Installation

1. Install **NeoForge 21.1.77+**
2. Download the latest release from [CurseForge](https://www.curseforge.com/minecraft/mc-mods/larbaco-auth/files)
3. Place the `.jar` file in the `mods/` folder
4. Start the server to generate the default configuration

### 🛠 Configuration

Edit `config/larbaco_auth.toml`:

```toml
[security]
max_attempts = 3
session_duration = "30m"
password_strength = "MEDIUM" # Options: LOW, MEDIUM, HIGH

[database]
type = "SQLITE" # Options: SQLITE, MYSQL
host = "localhost" # Used if MySQL is selected
```

---

## 📚 Usage

### Player Commands

```bash
/register <password> <confirm_password>   # First-time setup  
/login <password>                         # Log in to server  
/resetpassword                            # Request password reset  
```

### Admin Commands

```bash
/authadmin bypass <player>   # Temporarily bypass auth for a player  
/authadmin reset <player>    # Force password reset  
/authadmin logs              # View recent login attempts  
```

---

## 🔑 Permissions

| Node                   | Default | Description                        |
|------------------------|---------|------------------------------------|
| `larbaco.auth.admin`   | op      | Access admin commands              |
| `larbaco.auth.bypass`  | false   | Skip authentication                |
| `larbaco.auth.modify`  | false   | Modify other players' credentials  |

---

## ❓ FAQ

**Q: How do I recover admin access?**  
A: Use the console command:
```bash
/authadmin reset <yourname>
```

**Q: Is it compatible with other mods?**  
A: Generally yes. May conflict with other authentication mods.

---

## 📜 License

Licensed under the **GNU General Public License v3.0**.

You **must**:
- Disclose source code for any modifications
- Retain original copyright
- Include a copy of this license with distributions

---

## 🛠 Support

- **Issue Tracker**: Use [GitHub Issues](https://github.com/your-repo/issues)
- **Community Help**: Join our [Discord Server](https://discord.gg/your-invite-link)

---

Maintained with ❤️ by the **Larbaco Team**  
*Not affiliated with Mojang or Microsoft*
