import tkinter as tk
from tkinter import ttk, Menu, messagebox
import socket
import json
import subprocess
import threading
import requests

class PortKnockingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Knocking Tool")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        self.root.attributes('-topmost', True)
        self.root.after(1000, lambda: self.root.attributes('-topmost', False))
        self.configurations = []
        self.ping_process = None
        self.traceroute_process = None
        self.knock_process = None
        self.create_widgets()
        self.load_configurations()
        self.root.after(1000, self.display_public_ip_addresses)

    def create_widgets(self):
        # Menu
        self.menu = Menu(self.root)
        self.root.config(menu=self.menu)

        file_menu = Menu(self.menu, tearoff=0)
        file_menu.add_command(label="New", command=self.new_configuration)
        file_menu.add_command(label="Save", command=self.save_configuration)
        file_menu.add_command(label="Load", command=self.load_configuration)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu.add_cascade(label="File", menu=file_menu)

        # Help menu item
        help_menu = Menu(self.menu, tearoff=0)
        help_menu.add_command(label="Help", command=self.show_help)
        self.menu.add_cascade(label="Help", menu=help_menu)

        # Main Frame
        self.main_frame = tk.Frame(self.root)
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Public IP Display
        self.public_ip_frame = tk.Frame(self.main_frame)
        self.public_ip_frame.grid(row=0, column=0, pady=5, sticky="ew")
        self.public_ip_label_v4 = tk.Label(self.public_ip_frame, text="Public IPv4: ", font=("Helvetica", 12, "bold"), anchor="w")
        self.public_ip_label_v4.grid(row=0, column=0, sticky="ew")
        self.public_ip_value_v4 = tk.Label(self.public_ip_frame, text="", font=("Helvetica", 12, "bold"), anchor="e")
        self.public_ip_value_v4.grid(row=0, column=1, sticky="ew")
        self.public_ip_label_v6 = tk.Label(self.public_ip_frame, text="Public IPv6: ", font=("Helvetica", 12, "bold"), anchor="w")
        self.public_ip_label_v6.grid(row=1, column=0, sticky="ew")
        self.public_ip_value_v6 = tk.Label(self.public_ip_frame, text="", font=("Helvetica", 12, "bold"), anchor="e")
        self.public_ip_value_v6.grid(row=1, column=1, sticky="ew")

        self.check_ip_button = tk.Button(self.public_ip_frame, text="Check", command=self.display_public_ip_addresses)
        self.check_ip_button.grid(row=2, column=0, columnspan=2, pady=5)

        # Configuration Frame
        self.config_frame = tk.LabelFrame(self.main_frame, text="Configuration")
        self.config_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        self.ip_label = tk.Label(self.config_frame, text="Target IP/Hostname (IPv4/IPv6): *")
        self.ip_label.grid(row=0, column=0, sticky=tk.W)
        self.ip_entry = tk.Entry(self.config_frame)
        self.ip_entry.grid(row=0, column=1, columnspan=3, sticky=tk.EW)

        self.protocols = ["None", "TCP", "UDP"]

        self.port_entries = []
        for i in range(5):
            protocol_label = tk.Label(self.config_frame, text=f"Port {i+1} Protocol:" + (" *" if i < 2 else " (Optional):"))
            protocol_label.grid(row=i+1, column=0, sticky=tk.W)
            protocol_combobox = ttk.Combobox(self.config_frame, values=self.protocols, state="readonly")
            protocol_combobox.grid(row=i+1, column=1, sticky=tk.EW)
            protocol_combobox.current(0)

            port_label = tk.Label(self.config_frame, text=f"Port {i+1}:" + (" *" if i < 2 else " (Optional):"))
            port_label.grid(row=i+1, column=2, sticky=tk.W)
            port_entry = tk.Entry(self.config_frame)
            port_entry.grid(row=i+1, column=3, sticky=tk.EW)

            enable_var = tk.BooleanVar()
            enable_check = tk.Checkbutton(self.config_frame, variable=enable_var, command=lambda idx=i: self.toggle_optional_port(idx))
            enable_check.grid(row=i+1, column=4)

            self.port_entries.append((protocol_combobox, port_entry, enable_var, enable_check))

        self.validation_port_label = tk.Label(self.config_frame, text="Validation Port (Optional):")
        self.validation_port_label.grid(row=6, column=0, sticky=tk.W)
        self.validation_port_entry = tk.Entry(self.config_frame)
        self.validation_port_entry.grid(row=6, column=1, sticky=tk.EW)

        self.config_name_label = tk.Label(self.config_frame, text="Configuration Name:")
        self.config_name_label.grid(row=7, column=0, sticky=tk.W)
        self.config_name_entry = tk.Entry(self.config_frame)
        self.config_name_entry.grid(row=7, column=1, columnspan=3, sticky=tk.EW)

        # Buttons for Configuration
        self.config_button_frame = tk.Frame(self.config_frame)
        self.config_button_frame.grid(row=8, column=0, columnspan=4, pady=10)

        self.save_button = tk.Button(self.config_button_frame, text="Save Config", command=self.save_configuration)
        self.save_button.grid(row=0, column=0, padx=5)

        self.load_button = tk.Button(self.config_button_frame, text="Load Config", command=self.load_configuration)
        self.load_button.grid(row=0, column=1, padx=5)

        self.edit_button = tk.Button(self.config_button_frame, text="Edit Config", command=self.edit_configuration)
        self.edit_button.grid(row=0, column=2, padx=5)

        self.delete_button = tk.Button(self.config_button_frame, text="Delete Config", command=self.delete_configuration)
        self.delete_button.grid(row=0, column=3, padx=5)

        # Saved Configurations and Status/Logs Frame
        self.bottom_frame = tk.Frame(self.main_frame)
        self.bottom_frame.grid(row=2, column=0, padx=10, pady=5, sticky="nsew")
        self.main_frame.grid_rowconfigure(2, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.saved_configs_frame = tk.LabelFrame(self.bottom_frame, text="Saved Configurations")
        self.saved_configs_frame.grid(row=0, column=0, sticky="nsew")
        self.bottom_frame.grid_rowconfigure(0, weight=1)
        self.bottom_frame.grid_columnconfigure(0, weight=1)

        self.config_listbox = tk.Listbox(self.saved_configs_frame)
        self.config_listbox.pack(fill="both", expand=True)
        self.config_listbox.bind("<Double-Button-1>", self.load_configuration)

        self.status_frame = tk.LabelFrame(self.bottom_frame, text="Status and Logs")
        self.status_frame.grid(row=0, column=1, sticky="nsew")
        self.bottom_frame.grid_rowconfigure(0, weight=1)
        self.bottom_frame.grid_columnconfigure(1, weight=1)

        self.output_text = tk.Text(self.status_frame, height=10, wrap=tk.WORD)
        self.output_text.pack(fill="both", expand=True)
        self.output_text.config(state=tk.DISABLED)

        # Buttons for Actions
        self.button_frame = tk.Frame(self.main_frame)
        self.button_frame.grid(row=3, column=0, padx=10, pady=5, sticky="ew")
        self.button_frame.grid_columnconfigure(0, weight=1)

        self.knock_button = tk.Button(self.button_frame, text="KNOCK!", command=self.toggle_knock, font=("Helvetica", 12, "bold"))
        self.knock_button.grid(row=0, column=0, padx=5)

        self.tools_frame = tk.LabelFrame(self.main_frame, text="Tools")
        self.tools_frame.grid(row=4, column=0, padx=10, pady=5, sticky="ew")

        self.ping_button = tk.Button(self.tools_frame, text="PING", command=self.ping_target)
        self.ping_button.grid(row=0, column=1, padx=5)

        self.traceroute_button = tk.Button(self.tools_frame, text="TRACEROUTE", command=self.traceroute_target)
        self.traceroute_button.grid(row=0, column=2, padx=5)

        # Status Bar
        self.status_bar = tk.Label(self.root, text="Status: Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=1, column=0, sticky="ew")

        self.update_additional_ports_view()
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=0)

    def clear_status(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)

    def validate_ip_or_hostname(self, ip_or_hostname):
        try:
            socket.getaddrinfo(ip_or_hostname, None)
            return True
        except socket.error:
            return False

    def validate_port(self, port):
        try:
            port = int(port)
            return 1 <= port <= 65535
        except ValueError:
            return False

    def toggle_knock(self):
        if self.knock_process:
            self.stop_knock()
        else:
            self.knock_ports()

    def knock_ports(self):
        self.clear_status()
        ip_or_hostname = self.ip_entry.get()
        ports = [
            (self.port_entries[i][0].get(), self.port_entries[i][1].get())
            for i in range(5)
        ]
        validation_port = self.validation_port_entry.get()

        if not self.validate_ip_or_hostname(ip_or_hostname):
            self.status_bar.config(text="Status: Invalid IP/Hostname", fg="red")
            self.update_output("Invalid IP/Hostname. Please enter a valid IP address or hostname.")
            return

        for i in range(2):
            protocol, port = ports[i]
            if protocol == "None" or not self.validate_port(port):
                self.status_bar.config(text="Status: Invalid Ports", fg="red")
                self.update_output("Invalid Ports. Please select a protocol and enter valid ports for the required fields.")
                return

        self.status_bar.config(text=f"Status: Knocking on {ip_or_hostname}...", fg="blue")
        self.knock_button.config(text="STOP", bg="red")
        self.update_output("Knocking...")

        try:
            ip_list = socket.getaddrinfo(ip_or_hostname, None)
            ip = ip_list[0][4][0]
        except socket.error:
            self.status_bar.config(text="Status: Hostname Resolution Failed", fg="red")
            self.update_output("Hostname Resolution Failed. Unable to resolve the hostname.")
            self.knock_button.config(text="KNOCK!", bg="SystemButtonFace")
            return

        if validation_port:
            self.check_port_status(ip, int(validation_port), "before knock")

        self.knock_process = threading.Thread(target=self.perform_knock, args=(ip, ports, validation_port))
        self.knock_process.start()

    def perform_knock(self, ip, ports, validation_port):
        for protocol, port in ports:
            if protocol != "None" and self.validate_port(port):
                self.status_bar.config(text=f"Status: Knocking on {protocol} port {port}...", fg="blue")
                self.update_output(f"Knocking on {protocol} port {port}...")
                self.send_packet(ip, protocol, int(port))

        self.status_bar.config(text="Status: Knock Complete", fg="green")
        self.update_output("Knock Complete")

        if validation_port:
            self.check_port_status(ip, int(validation_port), "after knock")

        self.knock_process = None
        self.knock_button.config(text="KNOCK!", bg="SystemButtonFace")

    def stop_knock(self):
        if self.knock_process:
            self.knock_process = None
            self.status_bar.config(text="Status: Knock Stopped", fg="red")
            self.update_output("Knock Stopped")
            self.knock_button.config(text="KNOCK!", bg="SystemButtonFace")

    def send_packet(self, ip, protocol, port):
        try:
            sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                                 socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            sock.close()
        except socket.error:
            pass

    def check_port_status(self, ip, port, time):
        try:
            ip_type = socket.AF_INET6 if ":" in ip else socket.AF_INET
            sock = socket.socket(ip_type, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                status = "open"
            elif result == 10061:  # Connection refused
                status = "closed"
            else:
                status = "firewalled"
            self.update_output(f"Validation port {port} is {status} {time}.")
        except socket.error as e:
            self.update_output(f"Error checking port {port} status {time}: {e}")
        finally:
            sock.close()

    def save_configuration(self):
        ip_or_hostname = self.ip_entry.get()
        config_name = self.config_name_entry.get().strip()
        if not config_name:
            config_name = f"{ip_or_hostname}-{len(self.configurations) + 1}"
            self.config_name_entry.insert(0, config_name)
        ports = [
            (self.port_entries[i][0].get(), self.port_entries[i][1].get())
            for i in range(5)
        ]
        validation_port = self.validation_port_entry.get()

        self.configurations.append((config_name, {"ip": ip_or_hostname, "ports": ports, "validation_port": validation_port}))
        self.update_config_listbox()
        self.save_configurations_to_file()
        self.status_bar.config(text="Status: Configuration Saved", fg="green")
        self.update_output("Configuration Saved")

    def load_configuration(self, event=None):
        selected_index = self.config_listbox.curselection()
        if selected_index:
            config = self.configurations[selected_index[0]][1]
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, config["ip"])

            for i in range(5):
                self.port_entries[i][0].set(config["ports"][i][0])
                self.port_entries[i][1].delete(0, tk.END)
                self.port_entries[i][1].insert(0, config["ports"][i][1])
                if i >= 2:
                    self.port_entries[i][2].set(True if config["ports"][i][0] != "None" else False)

            self.validation_port_entry.delete(0, tk.END)
            self.validation_port_entry.insert(0, config["validation_port"])

            self.config_name_entry.delete(0, tk.END)
            self.config_name_entry.insert(0, self.configurations[selected_index[0]][0])
        self.update_additional_ports_view()

    def save_configurations_to_file(self):
        with open("configurations.json", "w") as file:
            json.dump(self.configurations, file)

    def load_configurations(self):
        try:
            with open("configurations.json", "r") as file:
                self.configurations = json.load(file)
            self.update_config_listbox()
        except FileNotFoundError:
            self.configurations = []

    def update_config_listbox(self):
        self.config_listbox.delete(0, tk.END)
        for name, _ in self.configurations:
            self.config_listbox.insert(tk.END, name)

    def delete_configuration(self):
        selected_index = self.config_listbox.curselection()
        if selected_index:
            del self.configurations[selected_index[0]]
            self.update_config_listbox()
            self.save_configurations_to_file()
            self.status_bar.config(text="Status: Configuration Deleted", fg="green")
            self.update_output("Configuration Deleted")

    def show_help(self):
        help_message = (
            "Port Knocking Tool Help\n\n"
            "This tool allows you to perform port knocking on a target host.\n\n"
            "Required Parameters:\n"
            "1. Target IP/Hostname: Enter the IP address or hostname of the target.\n"
            "2. Port 1: Enter a valid port number (1-65535) and select a protocol (TCP/UDP).\n"
            "3. Port 2: Enter a valid port number (1-65535) and select a protocol (TCP/UDP).\n\n"
            "Optional Parameters:\n"
            "4. Port 3: Enter a valid port number (1-65535) and select a protocol (TCP/UDP).\n"
            "5. Port 4: Enter a valid port number (1-65535) and select a protocol (TCP/UDP).\n"
            "6. Port 5: Enter a valid port number (1-65535) and select a protocol (TCP/UDP).\n"
            "7. Validation Port: Enter a port number to validate the knock.\n\n"
            "Other Features:\n"
            "- Configuration Name: Save the current settings with a name for future use.\n"
            "- Knock: Perform port knocking with the specified parameters.\n"
            "- Save: Save the current configuration.\n"
            "- Ping: Ping the target IP/Hostname.\n"
            "- Traceroute: Perform a traceroute to the target IP/Hostname.\n"
            "- Help: Show this help message.\n"
            "- Status Bar: Displays the status of the application's actions.\n\n"
            "© 2024 David Gonzalez and LAMBDA Strategies\n"
            "Visit: www.lambdastrategies.com"
        )

        messagebox.showinfo("Help", help_message)

    def update_output(self, text):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)

    def ping_target(self):
        if self.ping_process:
            self.stop_ping()
        else:
            self.clear_status()
            ip_or_hostname = self.ip_entry.get()
            if not self.validate_ip_or_hostname(ip_or_hostname):
                self.status_bar.config(text="Status: Invalid IP/Hostname", fg="red")
                self.update_output("Invalid IP/Hostname. Please enter a valid IP address or hostname.")
                return

            self.status_bar.config(text=f"Status: Pinging {ip_or_hostname}...", fg="blue")
            self.ping_button.config(text="STOP", bg="red")
            threading.Thread(target=self.run_ping, args=(ip_or_hostname,)).start()

    def stop_ping(self):
        if self.ping_process:
            self.ping_process.terminate()
            self.ping_process = None
            self.status_bar.config(text="Status: Ping Stopped", fg="red")
            self.update_output("Ping Stopped")
            self.ping_button.config(text="PING", bg="SystemButtonFace")

    def run_ping(self, ip_or_hostname):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        self.ping_process = subprocess.Popen(["ping", ip_or_hostname], stdout=subprocess.PIPE, text=True, startupinfo=startupinfo)
        for line in self.ping_process.stdout:
            self.update_output(line.strip())
        self.ping_process = None
        self.status_bar.config(text="Status: Ping Complete", fg="green")
        self.ping_button.config(text="PING", bg="SystemButtonFace")

    def traceroute_target(self):
        if self.traceroute_process:
            self.stop_traceroute()
        else:
            self.clear_status()
            ip_or_hostname = self.ip_entry.get()
            if not self.validate_ip_or_hostname(ip_or_hostname):
                self.status_bar.config(text="Status: Invalid IP/Hostname", fg="red")
                self.update_output("Invalid IP/Hostname. Please enter a valid IP address or hostname.")
                return

            self.status_bar.config(text=f"Status: Tracing route to {ip_or_hostname}...", fg="blue")
            self.traceroute_button.config(text="STOP", bg="red")
            threading.Thread(target=self.run_traceroute, args=(ip_or_hostname,)).start()

    def stop_traceroute(self):
        if self.traceroute_process:
            self.traceroute_process.terminate()
            self.traceroute_process = None
            self.status_bar.config(text="Status: Traceroute Stopped", fg="red")
            self.update_output("Traceroute Stopped")
            self.traceroute_button.config(text="TRACEROUTE", bg="SystemButtonFace")

    def run_traceroute(self, ip_or_hostname):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        self.traceroute_process = subprocess.Popen(["tracert", "-d", ip_or_hostname], stdout=subprocess.PIPE, text=True, startupinfo=startupinfo)
        for line in self.traceroute_process.stdout:
            self.update_output(line.strip())
        self.traceroute_process = None
        self.status_bar.config(text="Status: Traceroute Complete", fg="green")
        self.traceroute_button.config(text="TRACEROUTE", bg="SystemButtonFace")

    def toggle_optional_port(self, idx):
        if self.port_entries[idx][2].get():
            self.port_entries[idx][0].config(state="readonly")
            self.port_entries[idx][1].config(state=tk.NORMAL)
        else:
            self.port_entries[idx][0].set("None")
            self.port_entries[idx][0].config(state=tk.DISABLED)
            self.port_entries[idx][1].delete(0, tk.END)
            self.port_entries[idx][1].config(state=tk.DISABLED)

    def update_additional_ports_view(self):
        for i in range(5):
            if i < 2:
                self.port_entries[i][0].config(state="readonly")
                self.port_entries[i][1].config(state=tk.NORMAL)
            else:
                self.port_entries[i][0].config(state=tk.DISABLED)
                self.port_entries[i][1].config(state=tk.DISABLED)

        self.root.update_idletasks()
        self.root.geometry("")

    def new_configuration(self):
        self.ip_entry.delete(0, tk.END)
        self.config_name_entry.delete(0, tk.END)
        self.validation_port_entry.delete(0, tk.END)
        for protocol_combobox, port_entry, enable_var, enable_check in self.port_entries:
            protocol_combobox.set("None")
            port_entry.delete(0, tk.END)
            enable_var.set(False)
        self.update_additional_ports_view()

    def edit_configuration(self):
        selected_index = self.config_listbox.curselection()
        if selected_index:
            config = self.configurations[selected_index[0]][1]
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, config["ip"])

            for i in range(5):
                self.port_entries[i][0].set(config["ports"][i][0])
                self.port_entries[i][1].delete(0, tk.END)
                self.port_entries[i][1].insert(0, config["ports"][i][1])
                if i >= 2:
                    self.port_entries[i][2].set(True if config["ports"][i][0] != "None" else False)

            self.validation_port_entry.delete(0, tk.END)
            self.validation_port_entry.insert(0, config["validation_port"])

            self.config_name_entry.delete(0, tk.END)
            self.config_name_entry.insert(0, self.configurations[selected_index[0]][0])
        self.update_additional_ports_view()

    def display_public_ip_addresses(self):
        self.status_bar.config(text="Status: Fetching public IPs...", fg="blue")
        self.update_output("Fetching public IPs...")
        self.root.update_idletasks()

        def fetch_ip():
            ipv4_address = "Not Available"
            ipv6_address = "Not Available"
            try:
                ipv4_response = requests.get('https://api4.ipify.org?format=json').json()
                ipv4_address = ipv4_response.get('ip', 'Not Available')
            except requests.RequestException:
                pass

            try:
                ipv6_response = requests.get('https://api6.ipify.org?format=json').json()
                ipv6_address = ipv6_response.get('ip', 'Not Available')
            except requests.RequestException:
                pass

            self.public_ip_value_v4.config(text=ipv4_address)
            self.public_ip_value_v6.config(text=ipv6_address)
            self.status_bar.config(text="Status: Ready", fg="green")
            self.update_output("Public IPs fetched successfully.")

        threading.Thread(target=fetch_ip).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = PortKnockingApp(root)
    root.mainloop()
