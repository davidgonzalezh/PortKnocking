# PortknockingUtility

PortknockingUtility is a tool designed to perform port knocking on a target host, allowing users to manage configurations, perform network diagnostic tasks like ping and traceroute, and fetch public IP addresses.

## Features

- **Port Knocking**: Configure and send packets to specific ports on a target host.
- **Configuration Management**: Save, load, edit, and delete configurations.
- **Public IP Display**: Fetch and display public IPv4 and IPv6 addresses.
- **Network Diagnostics**: Ping and traceroute functionalities to diagnose network issues.
- **User-Friendly Interface**: Simple and intuitive GUI built with Tkinter.

## Installation

### Installer

1. Download the `PortknockingUtilityInstaller.exe` file from the [latest release](https://github.com/davidgonzalezh/PortKnock/blob/main/release/PortKnockUtilitySetup.exe).
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

### Configuration File

The configurations are saved in a JSON file named `configurations.json`. Each configuration contains the target IP/Hostname, ports and protocols, and a validation port if specified. The format of the JSON file is as follows:

```json
[
    {
        "configuration_name": {
            "ip": "target_ip_or_hostname",
            "ports": [
                ["protocol1", "port1"],
                ["protocol2", "port2"],
                ["protocol3", "port3"],
                ["protocol4", "port4"],
                ["protocol5", "port5"]
            ],
            "validation_port": "validation_port"
        }
    }
]
```
### Note

Note: If the ports do not show correctly when you load a configuration, double-click the configuration host in the list, and the ports will display correctly.
Help

For more detailed help and instructions, refer to the help.txt file included with the application or access it through the "Help" menu item in the application.

### License

This project is licensed under the MIT License. See the LICENSE file for details.

### Contact

For questions or feedback, please contact David Gonzalez and LAMBDA Strategies at your-email@example.com.

Visit our website: [LAMBDA Strategies ](www.lambdastrategies.com)

