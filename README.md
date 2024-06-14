# PortknockingUtility

PortknockingUtility is a tool designed to perform port knocking on a target host, allowing users to manage configurations, perform network diagnostic tasks like ping and traceroute, and fetch public IP addresses.

## Features

- **Port Knocking**: Configure and send packets to specific ports on a target host.
- **Configuration Management**: Save, load, edit, and delete configurations.
- **Public IP Display**: Fetch and display public IPv4 and IPv6 addresses.
- **Network Diagnostics**: Ping and traceroute functionalities to diagnose network issues.
- **User-Friendly Interface**: Simple and intuitive GUI built with Tkinter.

## Installation

### Download

You can download the latest version of PortknockingUtility from the [Releases](https://github.com/yourusername/PortknockingUtility/releases) page. Choose between the executable file and the installer.

### Executable

1. Download the `PortknockingUtility.exe` file from the [latest release](https://github.com/yourusername/PortknockingUtility/releases/latest).
2. Place the executable in a preferred directory.
3. Double-click the executable to run the application.

### Installer

1. Download the `PortknockingUtilityInstaller.exe` file from the [latest release](https://github.com/yourusername/PortknockingUtility/releases/latest).
2. Run the installer and follow the on-screen instructions to install PortknockingUtility on your system.
3. Launch the application from the start menu or desktop shortcut.

## Usage

### Main Window

The main window of PortknockingUtility consists of several sections:

- **Public IPs**: Displays the public IPv4 and IPv6 addresses. Use the "Check My IP" button to fetch the current public IP addresses.
- **Configuration**: Enter the target IP/Hostname, configure up to 5 ports and protocols, and specify a validation port if needed. Save and load configurations from this section.
- **Tools**: Use the "PING" and "TRACEROUTE" buttons to perform network diagnostics on the target host.
- **Config Management**: Manage saved configurations. Save new configurations, load existing ones, edit or delete them.
- **Status and Logs**: View status messages and logs of actions performed by the application.

### Performing Port Knocking

1. Enter the target IP/Hostname.
2. Configure the ports and protocols.
3. Optionally, specify a validation port.
4. Click "KNOCK!" to perform the port knocking sequence. The status and logs section will display the progress.

### Managing Configurations

- **Save Configuration**: Enter a configuration name or use the default naming schema (`host-date`). Click "Save Config" to save the current configuration.
- **Load Configuration**: Select a configuration from the list and click "Load Config" or double-click the configuration to load it.
- **Edit Configuration**: Load a configuration, make changes, and click "Save Config" to update it.
- **Delete Configuration**: Select a configuration from the list and click "Delete Config" to remove it.

## Help

For more detailed help and instructions, refer to the `help.txt` file included with the application or access it through the "Help" menu item in the application.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

For questions or feedback, please contact David Gonzalez and LAMBDA Strategies at [your-email@example.com](mailto:your-email@example.com).

Visit our website: [www.lambdastrategies.com](http://www.lambdastrategies.com)
