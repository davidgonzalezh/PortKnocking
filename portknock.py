import tkinter as tk
from tkinter import ttk, messagebox
import socket
import json
import subprocess
import threading

class PortKnockingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Knocking Tool")
        self.configurations = []
        self.create_widgets()
        self.load_configurations()

    def create_widgets(self):
        # IP Address / Hostname
        self.ip_label = tk.Label(self.root, text="Target IP/Hostname (IPv4/IPv6): *")
        self.ip_label.grid(row=0, column=0, sticky=tk.W)
        self.ip_entry = tk.Entry(self.root)
        self.ip_entry.grid(row=0, column=1, columnspan=3, sticky=tk.EW)
        self.ip_entry.bind("<Enter>", lambda e: self.show_tooltip(e, "Enter a valid IP address or hostname"))

        # Protocol Selection
        self.protocols = ["None", "TCP", "UDP"]

        # Port 1
        self.port1_protocol_label = tk.Label(self.root, text="Port 1 Protocol: *")
        self.port1_protocol_label.grid(row=1, column=0, sticky=tk.W)
        self.port1_protocol = ttk.Combobox(self.root, values=self.protocols, state="readonly")
        self.port1_protocol.grid(row=1, column=1, sticky=tk.EW)
        self.port1_protocol.current(0)
        self.port1_protocol.bind("<Enter>", lambda e: self.show_tooltip(e, "Select TCP or UDP for required ports"))

        self.port1_label = tk.Label(self.root, text="Port 1: *")
        self.port1_label.grid(row=1, column=2, sticky=tk.W)
        self.port1_entry = tk.Entry(self.root)
        self.port1_entry.grid(row=1, column=3, sticky=tk.EW)
        self.port1_entry.bind("<Enter>", lambda e: self.show_tooltip(e, "Enter a valid port number (1-65535)"))

        # Port 2
        self.port2_protocol_label = tk.Label(self.root, text="Port 2 Protocol: *")
        self.port2_protocol_label.grid(row=2, column=0, sticky=tk.W)
        self.port2_protocol = ttk.Combobox(self.root, values=self.protocols, state="readonly")
        self.port2_protocol.grid(row=2, column=1, sticky=tk.EW)
        self.port2_protocol.current(0)
        self.port2_protocol.bind("<Enter>", lambda e: self.show_tooltip(e, "Select TCP or UDP for required ports"))

        self.port2_label = tk.Label(self.root, text="Port 2: *")
        self.port2_label.grid(row=2, column=2, sticky=tk.W)
        self.port2_entry = tk.Entry(self.root)
        self.port2_entry.grid(row=2, column=3, sticky=tk.EW)
        self.port2_entry.bind("<Enter>", lambda e: self.show_tooltip(e, "Enter a valid port number (1-65535)"))

        # Optional Port 3
        self.port3_protocol_label = tk.Label(self.root, text="Port 3 Protocol (Optional):")
        self.port3_protocol_label.grid(row=3, column=0, sticky=tk.W)
        self.port3_protocol = ttk.Combobox(self.root, values=self.protocols, state="readonly")
        self.port3_protocol.grid(row=3, column=1, sticky=tk.EW)
        self.port3_protocol.current(0)
        self.port3_protocol.bind("<Enter>", lambda e: self.show_tooltip(e, "Select TCP or UDP for optional ports"))

        self.port3_label = tk.Label(self.root, text="Port 3 (Optional):")
        self.port3_label.grid(row=3, column=2, sticky=tk.W)
        self.port3_entry = tk.Entry(self.root)
        self.port3_entry.grid(row=3, column=3, sticky=tk.EW)
        self.port3_entry.bind("<Enter>", lambda e: self.show_tooltip(e, "Enter a valid port number (1-65535)"))

        # Optional Port 4
        self.port4_protocol_label = tk.Label(self.root, text="Port 4 Protocol (Optional):")
        self.port4_protocol_label.grid(row=4, column=0, sticky=tk.W)
        self.port4_protocol = ttk.Combobox(self.root, values=self.protocols, state="readonly")
        self.port4_protocol.grid(row=4, column=1, sticky=tk.EW)
        self.port4_protocol.current(0)
        self.port4_protocol.bind("<Enter>", lambda e: self.show_tooltip(e, "Select TCP or UDP for optional ports"))

        self.port4_label = tk.Label(self.root, text="Port 4 (Optional):")
        self.port4_label.grid(row=4, column=2, sticky=tk.W)
        self.port4_entry = tk.Entry(self.root)
        self.port4_entry.grid(row=4, column=3, sticky=tk.EW)
        self.port4_entry.bind("<Enter>", lambda e: self.show_tooltip(e, "Enter a valid port number (1-65535)"))

        # Validation Port
        self.validation_port_label = tk.Label(self.root, text="Validation Port (Optional):")
        self.validation_port_label.grid(row=5, column=0, sticky=tk.W)
        self.validation_port_entry = tk.Entry(self.root)
        self.validation_port_entry.grid(row=5, column=1, sticky=tk.EW)
        self.validation_port_entry.bind("<Enter>", lambda e: self.show_tooltip(e, "Enter a valid port number (1-65535)"))

        # Configuration Name
        self.config_name_label = tk.Label(self.root, text="Configuration Name:")
        self.config_name_label.grid(row=6, column=0, sticky=tk.W)
        self.config_name_entry = tk.Entry(self.root)
        self.config_name_entry.grid(row=6, column=1, columnspan=3, sticky=tk.EW)
        self.config_name_entry.bind("<Enter>", lambda e: self.show_tooltip(e, "Enter a name for this configuration"))

        # Buttons
        self.knock_button = tk.Button(self.root, text="KNOCK!", command=self.knock_ports)
        self.knock_button.grid(row=7, column=0, pady=10)
        self.knock_button.bind("<Enter>", lambda e: self.show_tooltip(e, "Initiate port knocking"))

        self.save_button = tk.Button(self.root, text="SAVE", command=self.save_configuration)
        self.save_button.grid(row=7, column=1, pady=10)
        self.save_button.bind("<Enter>", lambda e: self.show_tooltip(e, "Save the current configuration"))

        self.ping_button = tk.Button(self.root, text="PING", command=self.ping_target)
        self.ping_button.grid(row=7, column=2, pady=10)
        self.ping_button.bind("<Enter>", lambda e: self.show_tooltip(e, "Ping the target IP/Hostname"))

        self.traceroute_button = tk.Button(self.root, text="TRACEROUTE", command=self.traceroute_target)
        self.traceroute_button.grid(row=7, column=3, pady=10)
        self.traceroute_button.bind("<Enter>", lambda e: self.show_tooltip(e, "Traceroute to the target IP/Hostname"))

        self.help_button = tk.Button(self.root, text="HELP", command=self.show_help)
        self.help_button.grid(row=7, column=4, pady=10)
        self.help_button.bind("<Enter>", lambda e: self.show_tooltip(e, "Show help information"))

        # Status Bar
        self.status_bar = tk.Label(self.root, text="Status: Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=8, column=0, columnspan=5, sticky=tk.W + tk.E)

        # Output Text Box
        self.output_text = tk.Text(self.root, height=10, wrap=tk.WORD)
        self.output_text.grid(row=9, column=0, columnspan=5, sticky=tk.EW)
        self.output_text.config(state=tk.DISABLED)

        self.config_listbox = tk.Listbox(self.root)
        self.config_listbox.grid(row=10, column=0, columnspan=5, sticky=tk.EW)
        self.config_listbox.bind("<Double-Button-1>", self.load_configuration)
        self.config_listbox.bind("<Enter>", lambda e: self.show_tooltip(e, "Double-click to load a saved configuration"))

    def show_tooltip(self, event, text):
        tooltip = tk.Toplevel()
        tooltip.wm_overrideredirect(True)
        tooltip.wm_geometry(f"+{event.x_root + 10}+{event.y_root + 10}")
        label = tk.Label(tooltip, text=text, background="yellow", relief="solid", borderwidth=1)
        label.pack()
        tooltip.after(1500, tooltip.destroy)

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

    def knock_ports(self):
        ip_or_hostname = self.ip_entry.get()
        ports = [
            (self.port1_protocol.get(), self.port1_entry.get()),
            (self.port2_protocol.get(), self.port2_entry.get()),
            (self.port3_protocol.get(), self.port3_entry.get()),
            (self.port4_protocol.get(), self.port4_entry.get())
        ]
        validation_port = self.validation_port_entry.get()

        # Validate IP/Hostname and ports
        if not self.validate_ip_or_hostname(ip_or_hostname):
            self.status_bar.config(text="Status: Invalid IP/Hostname", fg="red")
            messagebox.showerror("Invalid IP/Hostname", "Please enter a valid IP address or hostname.")
            return

        for protocol, port in ports[:2]:
            if protocol == "None" or not self.validate_port(port):
                self.status_bar.config(text="Status: Invalid Ports", fg="red")
                messagebox.showerror("Invalid Ports", "Please select a protocol and enter valid ports for the required fields.")
                return

        self.status_bar.config(text="Status: Knocking...", fg="blue")
        self.update_output("Knocking...")

        # Resolve hostname to IP
        try:
            ip_list = socket.getaddrinfo(ip_or_hostname, None)
            ip = ip_list[0][4][0]
        except socket.error:
            self.status_bar.config(text="Status: Hostname Resolution Failed", fg="red")
            messagebox.showerror("Hostname Resolution Failed", "Unable to resolve the hostname.")
            return

        for protocol, port in ports:
            if protocol != "None" and self.validate_port(port):
                self.status_bar.config(text=f"Status: Knocking on {protocol} port {port}...", fg="blue")
                self.update_output(f"Knocking on {protocol} port {port}...")
                self.send_packet(ip, protocol, int(port))

        self.status_bar.config(text="Status: Knock Complete", fg="green")
        self.update_output("Knock Complete")

        if validation_port:
            if self.validate_port(validation_port):
                self.status_bar.config(text=f"Status: Validating on port {validation_port}...", fg="blue")
                self.update_output(f"Validating on port {validation_port}...")
                threading.Thread(target=self.validate_knock, args=(ip, int(validation_port))).start()
            else:
                self.status_bar.config(text="Status: Invalid Validation Port", fg="red")
                messagebox.showerror("Invalid Validation Port", "Please enter a valid validation port (1-65535).")
        else:
            self.status_bar.config(text="Status: Knock Complete without validation", fg="green")
            self.update_output("Knock Complete without validation")

    def send_packet(self, ip, protocol, port):
        try:
            sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                                 socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            sock.close()
        except socket.error:
            pass

    def validate_knock(self, ip, validation_port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, validation_port))
            self.status_bar.config(text="Status: Knock Validation Successful", fg="green")
            self.update_output("Knock Validation Successful")
            messagebox.showinfo("Knock Validation", "Knock validation successful!")
            sock.close()
        except socket.error:
            self.status_bar.config(text="Status: Knock Validation Failed", fg="red")
            self.update_output("Knock Validation Failed")
            messagebox.showerror("Knock Validation", "Knock validation failed.")

    def save_configuration(self):
        ip_or_hostname = self.ip_entry.get()
        config_name = self.config_name_entry.get().strip() or f"Config-{ip_or_hostname}"
        ports = [
            (self.port1_protocol.get(), self.port1_entry.get()),
            (self.port2_protocol.get(), self.port2_entry.get()),
            (self.port3_protocol.get(), self.port3_entry.get()),
            (self.port4_protocol.get(), self.port4_entry.get())
        ]
        validation_port = self.validation_port_entry.get()

        self.configurations.append((config_name, {"ip": ip_or_hostname, "ports": ports, "validation_port": validation_port}))
        self.update_config_listbox()
        self.save_configurations_to_file()
        self.status_bar.config(text="Status: Configuration Saved", fg="green")
        self.update_output("Configuration Saved")

    def load_configuration(self, event):
        selected_index = self.config_listbox.curselection()
        if selected_index:
            config = self.configurations[selected_index[0]][1]
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, config["ip"])

            self.port1_protocol.set(config["ports"][0][0])
            self.port1_entry.delete(0, tk.END)
            self.port1_entry.insert(0, config["ports"][0][1])

            self.port2_protocol.set(config["ports"][1][0])
            self.port2_entry.delete(0, tk.END)
            self.port2_entry.insert(0, config["ports"][1][1])

            self.port3_protocol.set(config["ports"][2][0])
            self.port3_entry.delete(0, tk.END)
            self.port3_entry.insert(0, config["ports"][2][1])

            self.port4_protocol.set(config["ports"][3][0])
            self.port4_entry.delete(0, tk.END)
            self.port4_entry.insert(0, config["ports"][3][1])

            self.validation_port_entry.delete(0, tk.END)
            self.validation_port_entry.insert(0, config["validation_port"])

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
            "6. Validation Port: Enter a port number to validate the knock.\n\n"
            "Other Features:\n"
            "- Configuration Name: Save the current settings with a name for future use.\n"
            "- Knock: Perform port knocking with the specified parameters.\n"
            "- Save: Save the current configuration.\n"
            "- Ping: Ping the target IP/Hostname.\n"
            "- Traceroute: Perform a traceroute to the target IP/Hostname.\n"
            "- Help: Show this help message.\n"
            "- Status Bar: Displays the status of the application's actions.\n"
        )
        messagebox.showinfo("Help", help_message)

    def update_output(self, text):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.config(state=tk.DISABLED)

    def ping_target(self):
        ip_or_hostname = self.ip_entry.get()
        if not self.validate_ip_or_hostname(ip_or_hostname):
            self.status_bar.config(text="Status: Invalid IP/Hostname", fg="red")
            messagebox.showerror("Invalid IP/Hostname", "Please enter a valid IP address or hostname.")
            return

        self.status_bar.config(text="Status: Pinging...", fg="blue")
        threading.Thread(target=self.run_ping, args=(ip_or_hostname,)).start()

    def run_ping(self, ip_or_hostname):
        result = subprocess.run(["ping", ip_or_hostname], stdout=subprocess.PIPE, text=True)
        self.update_output(result.stdout)
        self.status_bar.config(text="Status: Ping Complete", fg="green")

    def traceroute_target(self):
        ip_or_hostname = self.ip_entry.get()
        if not self.validate_ip_or_hostname(ip_or_hostname):
            self.status_bar.config(text="Status: Invalid IP/Hostname", fg="red")
            messagebox.showerror("Invalid IP/Hostname", "Please enter a valid IP address or hostname.")
            return

        self.status_bar.config(text="Status: Tracing route...", fg="blue")
        threading.Thread(target=self.run_traceroute, args=(ip_or_hostname,)).start()

    def run_traceroute(self, ip_or_hostname):
        result = subprocess.run(["tracert", ip_or_hostname], stdout=subprocess.PIPE, text=True)
        self.update_output(result.stdout)
        self.status_bar.config(text="Status: Traceroute Complete", fg="green")

if __name__ == "__main__":
    root = tk.Tk()
    app = PortKnockingApp(root)
    root.mainloop()
