# Home Assistant Add-on: Family Chore Tracker

![GitHub Release](https://img.shields.io/github/release/TadejBartol/ha-family-chore-tracker.svg)
![GitHub](https://img.shields.io/github/license/TadejBartol/ha-family-chore-tracker.svg)

A comprehensive family chore management system with points, rewards, and advanced statistics designed as a Home Assistant Add-on.

## ✨ Features

- **Multi-user Family Management**: Role-based access for different family members
- **Smart Task Scheduling**: Daily, weekly, monthly, and one-time tasks
- **Points & Rewards System**: Motivate family members with point-based incentives
- **Advanced Analytics**: Interactive charts and performance tracking
- **Collaborative Features**: Help other family members complete tasks
- **Home Assistant Integration**: Seamless integration with your smart home

## 🚀 Quick Start

### Prerequisites

- Home Assistant OS or Home Assistant Supervised
- Basic knowledge of Home Assistant Add-ons

### Installation

1. **Add Repository**:
   - Navigate to **Supervisor** → **Add-on Store**
   - Click the menu (three dots) → **Repositories**
   - Add: `https://github.com/TadejBartol/ha-family-chore-tracker`

2. **Install Add-on**:
   - Find "Family Chore Tracker" in the add-on store
   - Click "Install"

3. **Configure**:
   ```yaml
   database_path: "/data/chores.db"
   port: 3000
   log_level: "info"
   ssl: false
   ```

4. **Start**:
   - Click "Start"
   - Check logs for any errors
   - Access via "Open Web UI"

## 📱 Usage

### First Setup

1. **Admin Account**: Use default credentials `admin`/`admin123` (change immediately!)
2. **Create Users**: Add family members with appropriate roles
3. **Setup Tasks**: Create chore templates with points and frequencies
4. **Assign Tasks**: Use automatic assignment for recurring tasks

### Daily Use

- **Complete Tasks**: Check off completed chores to earn points
- **View Statistics**: Track progress and compare with family members
- **Redeem Rewards**: Spend points on predefined rewards
- **Help Others**: Assist family members after completing your own tasks

## 🏠 Home Assistant Integration

### Automations

The add-on exposes several API endpoints that can be used in Home Assistant automations:

```yaml
# Example: Notify when chores are overdue
automation:
  - alias: "Chore Reminder"
    trigger:
      platform: time
      at: "18:00:00"
    action:
      service: rest_command.check_overdue_chores
```

### Dashboard Cards

Create custom dashboard cards to display chore statistics in your Home Assistant interface.

## 🔧 Development

### Local Development

1. **Clone Repository**:
   ```bash
   git clone https://github.com/TadejBartol/ha-family-chore-tracker
   cd ha-family-chore-tracker
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Set Environment Variables**:
   ```bash
   export DATABASE_PATH="./data/chores.db"
   export PORT=3000
   export HASSIO=false
   ```

4. **Run Application**:
   ```bash
   npm start
   ```

### Building Add-on

The add-on uses GitHub Actions for automated builds across multiple architectures:

- `aarch64` (Raspberry Pi 4, etc.)
- `amd64` (Intel/AMD 64-bit)
- `armhf` (Raspberry Pi 2/3)
- `armv7` (ARM 32-bit)
- `i386` (Intel 32-bit)

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 Configuration Options

| Option | Description | Default | Required |
|--------|-------------|---------|----------|
| `database_path` | Path to SQLite database | `/data/chores.db` | ✅ |
| `port` | Application port | `3000` | ✅ |
| `log_level` | Logging verbosity | `info` | ❌ |
| `ssl` | Enable SSL/TLS | `false` | ❌ |
| `certfile` | SSL certificate file | `fullchain.pem` | ❌ |
| `keyfile` | SSL private key file | `privkey.pem` | ❌ |

## 🐛 Troubleshooting

### Common Issues

1. **Add-on won't start**:
   - Check add-on logs
   - Verify configuration syntax
   - Ensure database directory is writable

2. **Can't access web interface**:
   - Check if port is correctly configured
   - Try using Home Assistant ingress
   - Verify firewall settings

3. **Database errors**:
   - Check `/data` directory permissions
   - Verify database path in configuration
   - Restart add-on to reinitialize database

### Getting Help

- **GitHub Issues**: [Report bugs and request features](https://github.com/TadejBartol/ha-family-chore-tracker/issues)
- **Home Assistant Community**: [Discussion forum](https://community.home-assistant.io/)
- **Discord**: Join our community chat (link in repository)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Home Assistant community for inspiration and support
- Contributors and testers who helped improve the add-on
- Open source libraries that made this project possible

---

**Made with ❤️ for the Home Assistant community** 