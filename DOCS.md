# Home Assistant Add-on: Family Chore Tracker

![Supports aarch64 Architecture][aarch64-shield]
![Supports amd64 Architecture][amd64-shield]
![Supports armhf Architecture][armhf-shield]
![Supports armv7 Architecture][armv7-shield]
![Supports i386 Architecture][i386-shield]

A comprehensive family chore management system with points, rewards, and advanced statistics for Home Assistant.

## About

The Family Chore Tracker is a full-featured application designed to help families organize and track household chores. It includes:

- **Multi-user support** with role-based permissions
- **Point-based reward system** to motivate completion
- **Task categorization** by frequency (daily, weekly, monthly, one-time)
- **Advanced statistics** with interactive charts and analytics
- **Collaborative features** where family members can help each other
- **Automatic task scheduling** with recurring assignments
- **Beautiful responsive UI** optimized for all devices

## Installation

Follow these steps to get the add-on installed:

1. Navigate in your Home Assistant frontend to **Supervisor** → **Add-on Store**.
2. Add the repository URL: `https://github.com/[your-github-username]/ha-addons`
3. Find the "Family Chore Tracker" add-on and click it.
4. Click on the "INSTALL" button.

## How to use

1. Start the add-on.
2. Check the add-on log output for any errors.
3. Click "OPEN WEB UI" or navigate to the add-on URL.
4. Create your first admin user account.
5. Start adding family members and chores!

## Configuration

Add-on configuration:

```yaml
database_path: "/data/chores.db"
port: 3000
log_level: "info"
ssl: false
certfile: "fullchain.pem"
keyfile: "privkey.pem"
```

### Option: `database_path` (required)

The path where the SQLite database will be stored. Default is `/data/chores.db` which ensures persistence across restarts.

### Option: `port` (required)

The port the application will run on. Default is `3000`.

### Option: `log_level` (optional)

Controls the verbosity of log output. Available levels:
- `trace` - Very detailed debugging information
- `debug` - Debug information
- `info` - General information (default)
- `notice` - Important information
- `warning` - Warning messages
- `error` - Error messages only
- `fatal` - Fatal errors only

### Option: `ssl` (optional)

Enable SSL/TLS encryption. When enabled, you must provide certificate files.

### Option: `certfile` (optional)

The certificate file to use for SSL. Only used when SSL is enabled.

### Option: `keyfile` (optional)

The private key file to use for SSL. Only used when SSL is enabled.

## Features

### 🏠 **Multi-User Family Management**
- Create multiple user accounts with different roles
- Admin users can manage all family members
- Individual dashboards for each user

### 🎯 **Smart Task Management**
- **Daily tasks**: Reset every day at midnight
- **Weekly tasks**: Reset every Monday
- **Monthly tasks**: Reset on the 1st of each month
- **One-time tasks**: Visible only on creation day

### 🏆 **Points & Rewards System**
- Earn points for completing tasks
- Different point values for different task types
- Leaderboard to encourage friendly competition

### 📊 **Advanced Analytics**
- Interactive charts showing completion trends
- Performance comparisons between family members
- Activity heatmaps and productivity metrics
- Weekly/monthly/yearly statistics

### 🤝 **Collaborative Features**
- "Help Others" tab to assist family members
- Point sharing when helping others
- Must complete own tasks before helping others

### 🎨 **Beautiful Interface**
- Responsive design works on all devices
- Icon picker with 100+ emojis
- Modern, intuitive user interface
- Dark/light theme support

## Home Assistant Integration

The add-on integrates seamlessly with Home Assistant:

- **Supervisor integration**: Full management through HA UI
- **Persistent storage**: Data survives restarts and updates
- **SSL support**: Use your existing HA certificates
- **Ingress support**: Secure access through HA's authentication
- **Panel integration**: Direct access from HA sidebar

## API Endpoints

The application exposes several API endpoints that can be used for Home Assistant automations:

- `GET /api/user-stats` - Get user statistics
- `GET /api/users` - List all users
- `GET /api/chores` - Get all chores
- `POST /api/complete` - Complete a chore
- And many more...

## Troubleshooting

### Add-on won't start

Check the add-on logs for error messages. Common issues:

1. **Port already in use**: Change the port in configuration
2. **Database permissions**: Ensure `/data` directory is writable
3. **SSL certificate issues**: Check certificate file paths

### Can't access the web interface

1. Check that the add-on is running
2. Verify the port configuration
3. Try accessing via Home Assistant ingress
4. Check Home Assistant's reverse proxy settings

### Database issues

The SQLite database is automatically created on first run. If you encounter issues:

1. Check the `/data` directory permissions
2. Verify the database path in configuration
3. Restart the add-on to reinitialize

## Support

For support and feature requests:

- GitHub Issues: https://github.com/TadejBartol/ha-family-chore-tracker/issues
- Home Assistant Community: https://community.home-assistant.io/

## Contributing

Contributions are welcome! Please see our contributing guidelines.

## License

MIT License - see LICENSE file for details.

[aarch64-shield]: https://img.shields.io/badge/aarch64-yes-green.svg
[amd64-shield]: https://img.shields.io/badge/amd64-yes-green.svg
[armhf-shield]: https://img.shields.io/badge/armhf-yes-green.svg
[armv7-shield]: https://img.shields.io/badge/armv7-yes-green.svg
[i386-shield]: https://img.shields.io/badge/i386-yes-green.svg 