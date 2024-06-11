import tkinter as tk
from tkinter import ttk, messagebox, Menu
import socket
import json
import subprocess
import threading

class PortKnockingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Knocking Tool")
        self.configurations = []
        self.additional_ports_visible = [False, False, False]  # Track visibility of additional ports
        self.create_widgets()
        self.load_configurations()

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

        self.view_menu = Menu(self.menu, tearoff=0)
        self.view_menu.add_checkbutton(label="Show Port 3", command=lambda: self.toggle_port_visibility(2))
        self.view_menu.add_checkbutton(label="Show Port 4", command=lambda: self.toggle_port_visibility(3))
        self.view_menu.add_checkbutton(label="Show Port 5", command=lambda: self.toggle_port_visibility(4))
        self.menu.add_cascade(label="View", menu=self.view_menu)

        help_menu = Menu(self.menu, tearoff=0)
        help_menu.add_command(label="Help", command=self.show_help)
        self.menu.add_cascade(label="Help", menu=help_menu)

        # Main Frame
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Configuration Frame
        self.config_frame = tk.LabelFrame(self.main_frame, text="Configuration")
        self.config_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew")

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

            self.port_entries.append((protocol_combobox, port_entry))

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

        # Saved Configurations and Status/Logs Frame
        self.bottom_frame = tk.Frame(self.main_frame)
        self.bottom_frame.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")

        self.saved_configs_frame = tk.LabelFrame(self.bottom_frame, text="Saved Configurations")
        self.saved_configs_frame.grid(row=0, column=0, sticky="nsew")

        self.config_listbox = tk.Listbox(self.saved_configs_frame)
        self.config_listbox.pack(fill="both", expand=True)
        self.config_listbox.bind("<Double-Button-1>", self.load_configuration)

        self.status_frame = tk.LabelFrame(self.bottom_frame, text="Status and Logs")
        self.status_frame.grid(row=0, column=1, sticky="nsew")

        self.output_text = tk.Text(self.status_frame, height=10, wrap=tk.WORD)
        self.output_text.pack(fill="both", expand=True)
        self.output_text.config(state=tk.DISABLED)

        # Buttons for Actions
        self.button_frame = tk.Frame(self.main_frame)
        self.button_frame.grid(row=2, column=0, padx=10, pady=5, sticky="ew")

        self.knock_button = tk.Button(self.button_frame, text="KNOCK!", command=self.knock_ports)
        self.knock_button.grid(row=0, column=0, padx=5)

        self.ping_button = tk.Button(self.button_frame, text="PING", command=self.ping_target)
        self.ping_button.grid(row=0, column=1, padx=5)

        self.traceroute_button = tk.Button(self.button_frame, text="TRACEROUTE", command=self.traceroute_target)
        self.traceroute_button.grid(row=0, column=2, padx=5)

        # Status Bar
        self.status_bar = tk.Label(self.root, text="Status: Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.update_additional_ports_view()

        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

    def clear_status(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)

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
        self.clear_status()
        ip_or_hostname = self.ip_entry.get()
        ports = [
            (self.port_entries[i][0].get(), self.port_entries[i][1].get())
            for i in range(5)
        ]
        validation_port = self.validation_port_entry.get()

        # Validate IP/Hostname and ports
        if not self.validate_ip_or_hostname(ip_or_hostname):
            self.status_bar.config(text="Status: Invalid IP/Hostname", fg="red")
            messagebox.showerror("Invalid IP/Hostname", "Please enter a valid IP address or hostname.")
            return

        for i in range(2):
            protocol, port = ports[i]
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
                self.update_output("Invalid Validation Port")

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
            sock.close()
        except socket.timeout:
            self.status_bar.config(text="Status: Knock Validation Timed Out", fg="red")
            self.update_output("Knock Validation Timed Out")
        except socket.error:
            self.status_bar.config(text="Status: Knock Validation Failed", fg="red")
            self.update_output("Knock Validation Failed")

    def save_configuration(self):
        ip_or_hostname = self.ip_entry.get()
        config_name = self.config_name_entry.get().strip() or f"Config-{ip_or_hostname}"
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
        self.clear_status()
        ip_or_hostname = self.ip_entry.get()
        if not self.validate_ip_or_hostname(ip_or_hostname):
            self.status_bar.config(text="Status: Invalid IP/Hostname", fg="red")
            messagebox.showerror("Invalid IP/Hostname", "Please enter a valid IP address or hostname.")
            return

        self.status_bar.config(text="Status: Pinging...", fg="blue")
        threading.Thread(target=self.run_ping, args=(ip_or_hostname,)).start()

    def run_ping(self, ip_or_hostname):
        with subprocess.Popen(["ping", ip_or_hostname], stdout=subprocess.PIPE, text=True) as proc:
            for line in proc.stdout:
                self.update_output(line.strip())
        self.status_bar.config(text="Status: Ping Complete", fg="green")

    def traceroute_target(self):
        self.clear_status()
        ip_or_hostname = self.ip_entry.get()
        if not self.validate_ip_or_hostname(ip_or_hostname):
            self.status_bar.config(text="Status: Invalid IP/Hostname", fg="red")
            messagebox.showerror("Invalid IP/Hostname", "Please enter a valid IP address or hostname.")
            return

        self.status_bar.config(text="Status: Tracing route...", fg="blue")
        threading.Thread(target=self.run_traceroute, args=(ip_or_hostname,)).start()

    def run_traceroute(self, ip_or_hostname):
        with subprocess.Popen(["tracert", "-d", ip_or_hostname], stdout=subprocess.PIPE, text=True) as proc:
            for line in proc.stdout:
                self.update_output(line.strip())
        self.status_bar.config(text="Status: Traceroute Complete", fg="green")

    def toggle_view(self, view):
        if view == "status":
            if self.status_frame.grid_info():
                self.status_frame.grid_remove()
                self.view_menu.entryconfig("View Status", indicatoron=False)
            else:
                self.status_frame.grid(row=1, column=1, sticky="nsew")
                self.view_menu.entryconfig("View Status", indicatoron=True)
        elif view == "configs":
            if self.saved_configs_frame.grid_info():
                self.saved_configs_frame.grid_remove()
                self.view_menu.entryconfig("View Saved Configurations", indicatoron=False)
            else:
                self.saved_configs_frame.grid(row=1, column=0, sticky="nsew")
                self.view_menu.entryconfig("View Saved Configurations", indicatoron=True)

        self.root.update_idletasks()
        self.root.geometry("")

    def toggle_port_visibility(self, port_index):
        if port_index < len(self.additional_ports_visible) + 2:
            self.additional_ports_visible[port_index - 2] = not self.additional_ports_visible[port_index - 2]
            self.update_additional_ports_view()

    def update_additional_ports_view(self):
        for i in range(2, 5):
            if self.additional_ports_visible[i - 2]:
                self.port_entries[i][0].grid()
                self.port_entries[i][1].grid()
            else:
                self.port_entries[i][0].grid_remove()
                self.port_entries[i][1].grid_remove()

        self.root.update_idletasks()
        self.root.geometry("")

    def new_configuration(self):
        self.ip_entry.delete(0, tk.END)
        self.config_name_entry.delete(0, tk.END)
        self.validation_port_entry.delete(0, tk.END)
        for protocol_combobox, port_entry in self.port_entries:
            protocol_combobox.set("None")
            port_entry.delete(0, tk.END)

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

            self.validation_port_entry.delete(0, tk.END)
            self.validation_port_entry.insert(0, config["validation_port"])

            self.config_name_entry.delete(0, tk.END)
            self.config_name_entry.insert(0, self.configurations[selected_index[0]][0])

if __name__ == "__main__":
    root = tk.Tk()
    app = PortKnockingApp(root)
    root.mainloop()
