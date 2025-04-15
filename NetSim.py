import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from PIL import Image, ImageTk
import networkx as nx
import random
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
from datetime import datetime
import json
import re


class DeviceType:
    SERVER = "Server"
    SWITCH = "Switch"
    ACCESS_POINT = "Access-Point"
    ROUTER = "Router"
    COMPUTER = "Computer"
    FIREWALL = "Firewall"

# Class bt3ml represent le different types of devices bl names we el ip addresses
class AdvancedDevice:
    def __init__(self, name, ip_address, device_type):
        self.name = name
        self.ip_address = ip_address
        self.mac_address = self.generate_mac_address()
        self.device_type = device_type

    @staticmethod
    def generate_mac_address():
        return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])

    def to_dict(self):
        return {
            'name': self.name,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'device_type': self.device_type
        }

    @classmethod
    def from_dict(cls, data):
        device = cls(data['name'], data['ip_address'], data['device_type'])
        device.mac_address = data['mac_address']
        return device

class NetworkPacket:
    def __init__(self, source, destination, protocol, payload, speed=1.0):
        self.source = source
        self.destination = destination
        self.protocol = protocol
        self.payload = payload
        self.timestamp = datetime.now()
        self.status = "Pending"
        self.path = []
        self.current_position = 0
        self.speed = speed
        self.rtt = None
        self.start_time = None
    
    def to_dict(self):
        return {
            'source': self.source,
            'destination': self.destination,
            'protocol': self.protocol,
            'payload': self.payload,
            'timestamp': self.timestamp.isoformat(),
            'status': self.status,
            'path': self.path,
            'current_position': self.current_position,
            'speed': self.speed,
            'rtt': self.rtt
        }
    
    @classmethod
    def from_dict(cls, data):
        packet = cls(
            source=data['source'],
            destination=data['destination'],
            protocol=data['protocol'],
            payload=data['payload'],
            speed=data['speed']
        )
        packet.timestamp = datetime.fromisoformat(data['timestamp'])
        packet.status = data['status']
        packet.path = data['path']
        packet.current_position = data['current_position']
        packet.rtt = data['rtt']
        return packet
    
    def start_transmission(self):
        self.start_time = time.time()

    def complete_transmission(self):
        if self.start_time:
            self.rtt = (time.time() - self.start_time) * 1000  # Convert to milliseconds

class PacketAnalyzer: #capture packets and analyses them
    def __init__(self):
        self.captured_packets = []
        self.current_simulation = None

    def capture_packet(self, packet):
        self.captured_packets.append(packet)

    def to_dict(self):
        return {
            'captured_packets': [packet.to_dict() for packet in self.captured_packets]
        }
    
    @classmethod
    def from_dict(cls, data):
        analyzer = cls()
        analyzer.captured_packets = [NetworkPacket.from_dict(packet_data) 
                                    for packet_data in data['captured_packets']]
        return analyzer
    
    def get_packet_details(self):
        details = []
        for packet in self.captured_packets:
            rtt_info = f"RTT: {packet.rtt:.2f}ms" if packet.rtt is not None else "RTT: N/A"
            details.append(
                f"Time: {packet.timestamp.strftime('%H:%M:%S')} | "
                f"Source: {packet.source} -> Destination: {packet.destination} | "
                f"Protocol: {packet.protocol} | Status: {packet.status} | "
                f"Speed: {packet.speed} | {rtt_info}"
            )
        return details

    def update_simulation_status(self, packet, status):
        packet.status = status
        if status == "In Progress":
            packet.start_transmission()
        elif status == "Completed":
            packet.complete_transmission()
# da el by load el GUI nfso
class AdvancedNetworkSimulator:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Net-Sim")
        self.root.geometry("1400x800")

        self.devices = {}
        self.network_topology = nx.Graph()
        self.device_icons = {}
        self.packet_icon = None
        self.packet_analyzer = PacketAnalyzer()
        self.selected_device = None
        self.offset_x = 0
        self.offset_y = 0
        self.simulation_active = False
        self.packet_objects = {}

        self.load_icons()
        self.create_menu()
        self.create_split_gui()
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Simulation", command=self.save_simulation)
        file_menu.add_command(label="Load Simulation", command=self.load_simulation)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
    #  da el m5ly el gui y2sm el window l 2
    def create_split_gui(self):
        
        self.main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        self.topology_frame = ttk.Frame(self.main_container)
        self.main_container.add(self.topology_frame, weight=50)
        
        self.analysis_frame = ttk.Frame(self.main_container)
        self.main_container.add(self.analysis_frame, weight=50)

        self.create_topology_panel()
        self.create_packet_analysis_panel()

    def create_topology_panel(self):
        topology_panel = ttk.LabelFrame(self.topology_frame, text="Network Topology")
        topology_panel.pack(fill="both", expand=True, padx=5, pady=5)

        self.topology_canvas = tk.Canvas(topology_panel, bg="white")
        self.topology_canvas.pack(fill="both", expand=True)

        toolbar = ttk.Frame(topology_panel)
        toolbar.pack(fill="x", padx=5, pady=5)

        ttk.Button(toolbar, text="Add Device", command=self.add_device).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Add Link", command=self.add_link).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Remove Link", command=self.remove_link).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Remove Device", command=self.remove_device).pack(side="left", padx=2)
        ttk.Button(toolbar, text="Edit Device", command=self.edit_device).pack(side="left", padx=2)

        self.topology_canvas.bind("<Button-1>", self.on_click)
        self.topology_canvas.bind("<B1-Motion>", self.on_drag)
        

    def edit_device(self):
        if not self.selected_device:
            messagebox.showinfo("Info", "Please select a device first.")
            return

        device = self.devices[self.selected_device]
        edit_window = tk.Toplevel(self.root)
        edit_window.title(f"Edit Device: {device.name}")
        edit_window.geometry("300x200")

        # IP Address
        ttk.Label(edit_window, text="IP Address:").pack(pady=5)
        ip_var = tk.StringVar(value=device.ip_address)
        ip_entry = ttk.Entry(edit_window, textvariable=ip_var)
        ip_entry.pack(pady=5)

        # MAC Address
        ttk.Label(edit_window, text="MAC Address:").pack(pady=5)
        mac_var = tk.StringVar(value=device.mac_address)
        mac_entry = ttk.Entry(edit_window, textvariable=mac_var)
        mac_entry.pack(pady=5)

        def validate_and_save():
            # Validate IP address
            ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
            if not ip_pattern.match(ip_var.get()):
                messagebox.showerror("Error", "Invalid IP address format")
                return

            # Validate MAC address
            mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
            if not mac_pattern.match(mac_var.get()):
                messagebox.showerror("Error", "Invalid MAC address format")
                return

            device.ip_address = ip_var.get()
            device.mac_address = mac_var.get()
            edit_window.destroy()
            self.refresh_topology()

        ttk.Button(edit_window, text="Save", command=validate_and_save).pack(pady=10)
    
    def save_simulation(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if not file_path:
            return

        simulation_data = {
            'devices': {name: device.to_dict() for name, device in self.devices.items()},
            'topology': list(self.network_topology.edges),
            'packet_analyzer': self.packet_analyzer.to_dict()
        }
        # exeption handeling
        try:
            with open(file_path, 'w') as f:
                json.dump(simulation_data, f, indent=4)
            messagebox.showinfo("Success", "Simulation saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save simulation: {str(e)}")
    
    def load_simulation(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json")]
        )
        if not file_path:
            return
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            # Clear current simulation
            self.devices.clear()
            self.network_topology.clear()
            # Load devices
            for name, device_data in data['devices'].items():
                self.devices[name] = AdvancedDevice.from_dict(device_data)
            # Load topology
            for edge in data['topology']:
                self.network_topology.add_edge(edge[0], edge[1])
            # Load packet analyzer data
            if 'packet_analyzer' in data:
                self.packet_analyzer = PacketAnalyzer.from_dict(data['packet_analyzer'])
                self.update_packet_list()
            self.refresh_topology()
            messagebox.showinfo("Success", "Simulation loaded successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load simulation: {str(e)}")
    # Gui for analyzing packets
    def create_packet_analysis_panel(self):
        analysis_panel = ttk.LabelFrame(self.analysis_frame, text="Packet Analysis")
        analysis_panel.pack(fill="both", expand=True, padx=5, pady=5)

        # Make the packet list larger
        list_frame = ttk.Frame(analysis_panel)
        list_frame.pack(fill="both", expand=True, padx=5, pady=5)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")

        # Increased height for better visibility
        self.packet_list = tk.Listbox(list_frame, height=20, yscrollcommand=scrollbar.set)
        self.packet_list.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.packet_list.yview)

        # Control buttons
        control_frame = ttk.Frame(analysis_panel)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(control_frame, text="Create New Packet", command=self.simulate_packet).pack(side="left", padx=5)
        
        self.start_button = ttk.Button(control_frame, text="Start Simulation", command=self.start_simulation)
        self.start_button.pack(side="left", padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Simulation", command=self.stop_simulation)
        self.stop_button.pack(side="left", padx=5)
        self.stop_button["state"] = "disabled"
    
    def remove_link(self):
        if len(self.devices) < 2:
            messagebox.showerror("Error", "Add at least two devices to remove a link.")
            return

        link_window = tk.Toplevel(self.root)
        link_window.title("Remove Link")
        link_window.geometry("300x200")

        device1_name_var = tk.StringVar()
        device2_name_var = tk.StringVar()

        ttk.Label(link_window, text="Select the first device:").pack(pady=5)
        device1_dropdown = ttk.Combobox(
            link_window, textvariable=device1_name_var, values=list(self.devices.keys()), state="readonly"
        )
        device1_dropdown.pack(pady=5)

        ttk.Label(link_window, text="Select the second device:").pack(pady=5)
        device2_dropdown = ttk.Combobox(
            link_window, textvariable=device2_name_var, values=list(self.devices.keys()), state="readonly"
        )
        device2_dropdown.pack(pady=5)

        def confirm_remove():
            device1_name = device1_name_var.get()
            device2_name = device2_name_var.get()
            if not device1_name or not device2_name:
                messagebox.showerror("Error", "Please select two devices.")
                return
            if device1_name == device2_name:
                messagebox.showerror("Error", "Cannot remove link from device to itself.")
                return
            if not self.network_topology.has_edge(device1_name, device2_name):
                messagebox.showerror("Error", "No link exists between these devices.")
                return

            self.network_topology.remove_edge(device1_name, device2_name)
            self.refresh_topology()
            link_window.destroy()
            messagebox.showinfo("Success", f"Link between {device1_name} and {device2_name} has been removed.")

        ttk.Button(link_window, text="Remove Link", command=confirm_remove).pack(pady=10)
    #animation bta3 el packets w hya bttb3t
    def animate_packet(self, packet, start_pos, end_pos, callback):
        if packet not in self.packet_objects:
            self.packet_objects[packet] = self.topology_canvas.create_image(
                start_pos[0], start_pos[1],
                image=self.packet_icon
            )

        # Adjust animation steps based on packet speed
        base_steps = 50
        steps = int(base_steps / packet.speed)
        dx = (end_pos[0] - start_pos[0]) / steps
        dy = (end_pos[1] - start_pos[1]) / steps
        
        def move_step(step=0):
            if step < steps and self.simulation_active:
                x = start_pos[0] + dx * step
                y = start_pos[1] + dy * step
                self.topology_canvas.coords(
                    self.packet_objects[packet],
                    x, y
                )
                self.root.after(20, lambda: move_step(step + 1))
            else:
                if callback:
                    callback()

        move_step()

    def calculate_packet_path(self, source, destination):
        try:
            path = nx.shortest_path(self.network_topology, source, destination)
            return path
        except nx.NetworkXNoPath:
            return None

    def simulate_next_packet(self):
        if not self.simulation_active:
            return

        pending_packets = [p for p in self.packet_analyzer.captured_packets if p.status == "Pending"]
        if not pending_packets:
            self.stop_simulation()
            messagebox.showinfo("Simulation Complete", "All packets have been processed.")
            return

        packet = pending_packets[0]
        self.packet_analyzer.update_simulation_status(packet, "In Progress")
        self.update_packet_list()

        # Calculate path
        path = self.calculate_packet_path(packet.source, packet.destination)
        if not path:
            messagebox.showerror("Error", f"No valid path between {packet.source} and {packet.destination}")
            self.packet_analyzer.update_simulation_status(packet, "Failed")
            self.update_packet_list()
            self.root.after(500, self.simulate_next_packet)
            return

        packet.path = path
        self.animate_packet_along_path(packet, 0)

    def animate_packet_along_path(self, packet, path_index):
        if not self.simulation_active or path_index >= len(packet.path) - 1:
            if self.simulation_active:
                self.packet_analyzer.update_simulation_status(packet, "Completed")
                self.update_packet_list()
                self.root.after(500, self.simulate_next_packet)
            return

        current_node = packet.path[path_index]
        next_node = packet.path[path_index + 1]

        # Get positions of current and next nodes
        current_pos = self.get_device_position(current_node)
        next_pos = self.get_device_position(next_node)

        self.highlight_packet_path(packet, next_node)

        # Animate packet movement
        self.animate_packet(
            packet,
            current_pos,
            next_pos,
            lambda: self.animate_packet_along_path(packet, path_index + 1)
        )
    #b3d ma bn3ml select lel device bygeb el name bta3o wel function el t7t btgeb el icon
    def get_device_position(self, device_name):
        items = self.topology_canvas.find_withtag(device_name)
        if items:
            return self.topology_canvas.coords(items[0])[:2]
        return (0, 0)
    def load_icons(self):
        try:
            self.device_icons = {
                DeviceType.SERVER: ImageTk.PhotoImage(Image.open("icons/server.png").resize((40, 40))),
                DeviceType.SWITCH: ImageTk.PhotoImage(Image.open("icons/switch.png").resize((40, 40))),
                DeviceType.ACCESS_POINT: ImageTk.PhotoImage(Image.open("icons/access_point.png").resize((40, 40))),
                DeviceType.ROUTER: ImageTk.PhotoImage(Image.open("icons/router.png").resize((40, 40))),
                DeviceType.COMPUTER: ImageTk.PhotoImage(Image.open("icons/computer.png").resize((40, 40))),
                DeviceType.FIREWALL: ImageTk.PhotoImage(Image.open("icons/firewall.png").resize((40, 40))),
            }
            self.packet_icon = ImageTk.PhotoImage(Image.open("icons/packet.png").resize((20, 20)))
        except FileNotFoundError:
            messagebox.showerror("Error", "Device icons not found. Please ensure all icon files are present in the icons directory.")
            self.root.destroy()
        
    def add_device(self):
        add_device_window = tk.Toplevel(self.root)
        add_device_window.title("Add Device")
        add_device_window.geometry("300x200")
        
        ttk.Label(add_device_window, text="Select Device Type:").pack(pady=10)
        device_type_var = tk.StringVar()
        device_type_dropdown = ttk.Combobox(
            add_device_window,
            textvariable=device_type_var,
            values=[getattr(DeviceType, attr) for attr in dir(DeviceType) if not attr.startswith("__")],
            state="readonly"
        )
        device_type_dropdown.pack(pady=5)
        
        def confirm_selection():
            device_type = device_type_var.get()
            if not device_type:
                messagebox.showerror("Error", "Please select a device type.")
                return
            
            device_name = f"{device_type}-{len(self.devices) + 1}"
            ip_address = f"192.168.1.{len(self.devices) + 1}"
            device = AdvancedDevice(device_name, ip_address, device_type)
            
            self.devices[device_name] = device
            self.network_topology.add_node(device_name)
            self.refresh_topology()
            
            add_device_window.destroy()
        
        ttk.Button(add_device_window, text="Add Device", command=confirm_selection).pack(pady=10)
        
    def remove_device(self):
        if not self.devices:
            messagebox.showerror("Error", "No devices to remove.")
            return

        remove_window = tk.Toplevel(self.root)
        remove_window.title("Remove Device")
        remove_window.geometry("300x150")

        device_var = tk.StringVar()
        
        ttk.Label(remove_window, text="Select device to remove:").pack(pady=5)
        device_dropdown = ttk.Combobox(
            remove_window,
            textvariable=device_var,
            values=list(self.devices.keys()),
            state="readonly"
        )
        device_dropdown.pack(pady=5)
        
        def confirm_remove():
            device_name = device_var.get()
            if not device_name:
                messagebox.showerror("Error", "Please select a device.")
                return

            # Remove related packets
            self.packet_analyzer.captured_packets = [
                p for p in self.packet_analyzer.captured_packets
                if p.source != device_name and p.destination != device_name
            ]

            # Remove from topology and devices
            self.network_topology.remove_node(device_name)
            del self.devices[device_name]

            self.refresh_topology()
            self.update_packet_list()
            remove_window.destroy()
            messagebox.showinfo("Success", f"Device {device_name} has been removed.")

        ttk.Button(remove_window, text="Remove Device", command=confirm_remove).pack(pady=10)
    
    def add_link(self):
        if len(self.devices) < 2:
            messagebox.showerror("Error", "Add at least two devices to create a link.")
            return

        link_window = tk.Toplevel(self.root)
        link_window.title("Link Devices")
        link_window.geometry("300x200")

        device1_name_var = tk.StringVar()
        device2_name_var = tk.StringVar()

        ttk.Label(link_window, text="Select the first device:").pack(pady=5)
        device1_dropdown = ttk.Combobox(
            link_window, textvariable=device1_name_var, values=list(self.devices.keys()), state="readonly"
        )
        device1_dropdown.pack(pady=5)

        ttk.Label(link_window, text="Select the second device:").pack(pady=5)
        device2_dropdown = ttk.Combobox(
            link_window, textvariable=device2_name_var, values=list(self.devices.keys()), state="readonly"
        )
        device2_dropdown.pack(pady=5)

        def confirm_link():
            device1_name = device1_name_var.get()
            device2_name = device2_name_var.get()
            if not device1_name or not device2_name:
                messagebox.showerror("Error", "Please select two devices.")
                return
            if device1_name == device2_name:
                messagebox.showerror("Error", "Cannot link a device to itself.")
                return
            if self.network_topology.has_edge(device1_name, device2_name):
                messagebox.showerror("Error", "These devices are already linked.")
                return

            self.network_topology.add_edge(device1_name, device2_name)
            self.refresh_topology()
            link_window.destroy()

        ttk.Button(link_window, text="Link Devices", command=confirm_link).pack(pady=10)
        
    def simulate_packet(self):
        if len(self.devices) < 2:
            messagebox.showerror("Error", "At least two devices are required for packet simulation.")
            return

        simulation_window = tk.Toplevel(self.root)
        simulation_window.title("Create Packet")
        simulation_window.geometry("300x300")

        source_var = tk.StringVar()
        dest_var = tk.StringVar()
        protocol_var = tk.StringVar(value="TCP")
        speed_var = tk.DoubleVar(value=1.0)

    # Source device selection
        ttk.Label(simulation_window, text="Source Device:").pack(pady=5)
        source_combo = ttk.Combobox(
            simulation_window,
            textvariable=source_var,
            values=list(self.devices.keys()),
            state="readonly"
        )
        source_combo.pack(pady=5)

    # Destination device selection
        ttk.Label(simulation_window, text="Destination Device:").pack(pady=5)
        dest_combo = ttk.Combobox(
            simulation_window,
            textvariable=dest_var,
            values=list(self.devices.keys()),
            state="readonly"
        )
        dest_combo.pack(pady=5)

    # Protocol selection
        protocol_frame = ttk.LabelFrame(simulation_window, text="Protocol Selection")
        protocol_frame.pack(pady=10, padx=5, fill="x")

        protocols = ["TCP", "UDP", "ICMP"]
        for protocol in protocols:
            ttk.Radiobutton(
                protocol_frame,
                text=protocol,
                variable=protocol_var,
                value=protocol
            ).pack(side="left", padx=5)

    # Speed selection
        speed_frame = ttk.LabelFrame(simulation_window, text="Packet Speed")
        speed_frame.pack(pady=10, padx=5, fill="x")
    
        ttk.Scale(
            speed_frame,
            from_=0.1,
            to=2.0,
            variable=speed_var,
            orient="horizontal"
        ).pack(side="left", padx=5, fill="x", expand=True)
    
        ttk.Label(speed_frame, textvariable=tk.StringVar(value="×")).pack(side="left")

        def create_packet():
            source = source_var.get()
            destination = dest_var.get()
            protocol = protocol_var.get()
            speed = speed_var.get()

            if not source or not destination:
                messagebox.showerror("Error", "Please select both source and destination devices.")
                return
            
            if source == destination:
                messagebox.showerror("Error", "Source and destination must be different.")
                return

        # Verify path exists before creating packet
            try:
                path = nx.shortest_path(self.network_topology, source, destination)
            except nx.NetworkXNoPath:
                messagebox.showerror(
                    "Error", 
                    "No valid path exists between selected devices. Please ensure devices are connected."
                )
                return
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}")
                return
            # Verify path exists before creating packet
            try:
                packet = NetworkPacket(
                    source=source,
                    destination=destination,
                    protocol=protocol,
                    payload="Test Payload",
                    speed=speed
                )
                self.packet_analyzer.capture_packet(packet)
                self.update_packet_list()
                simulation_window.destroy()
                messagebox.showinfo("Success", "Packet created successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create packet: {str(e)}")

        ttk.Button(
            simulation_window,
            text="Create Packet",
            command=create_packet
        ).pack(pady=10)
            
    def start_simulation(self):
        if not self.packet_analyzer.captured_packets:
            messagebox.showinfo("No Packets", "Please create packets first.")
            return

        self.simulation_active = True
        self.start_button["state"] = "disabled"
        self.stop_button["state"] = "normal"
        self.simulate_next_packet()
    
    def stop_simulation(self):
        self.simulation_active = False
        self.start_button["state"] = "normal"
        self.stop_button["state"] = "disabled"
        
        # Clean up any remaining packet objects
        for packet in list(self.packet_objects.keys()):
            self.topology_canvas.delete(self.packet_objects[packet])
            del self.packet_objects[packet]
        
    def update_packet_list(self):
        self.packet_list.delete(0, tk.END)
        for detail in self.packet_analyzer.get_packet_details():
            self.packet_list.insert(tk.END, detail)
        self.packet_list.see(tk.END)
    
    def on_click(self, event):
        items = self.topology_canvas.find_closest(event.x, event.y)
        if items:
            tags = self.topology_canvas.gettags(items[0])
            if tags:
                self.selected_device = tags[0]
                coords = self.topology_canvas.coords(items[0])
                self.offset_x = event.x - coords[0]
                self.offset_y = event.y - coords[1]
                
    def on_drag(self, event):
        if self.selected_device:
            items = self.topology_canvas.find_withtag(self.selected_device)
            if items:
                new_x = event.x - self.offset_x
                new_y = event.y - self.offset_y
                
                for item in items:
                    current_x, current_y = self.topology_canvas.coords(item)[:2]
                    dx = new_x - current_x
                    dy = new_y - current_y
                    self.topology_canvas.move(item, dx, dy)
                
                self.refresh_topology()
                
    def refresh_topology(self):
        positions = {}
        for node in self.network_topology.nodes:
            items = self.topology_canvas.find_withtag(node)
            if items:
                coords = self.topology_canvas.coords(items[0])
                if coords:
                    positions[node] = (coords[0], coords[1])
        
        self.topology_canvas.delete("all")

        for node in self.network_topology.nodes:
            if node in positions:
                x, y = positions[node]
            else:
                canvas_width = self.topology_canvas.winfo_width() or 800
                canvas_height = self.topology_canvas.winfo_height() or 600
                padding = 50
                cols = max(1, (canvas_width - 2 * padding) // 100)
                index = list(self.network_topology.nodes).index(node)
                x = padding + (index % cols) * ((canvas_width - 2 * padding) / cols)
                y = padding + (index // cols) * ((canvas_height - 2 * padding) / (len(self.network_topology.nodes) // cols + 1))

            icon = self.device_icons.get(self.devices[node].device_type)
            if icon:
                self.topology_canvas.create_image(x, y, image=icon, tags=node)
            self.topology_canvas.create_text(x, y + 25, text=node, fill="black", tags=node)

        for edge in self.network_topology.edges:
            device1, device2 = edge
            items1 = self.topology_canvas.find_withtag(device1)
            items2 = self.topology_canvas.find_withtag(device2)
            if items1 and items2:
                x1, y1 = self.topology_canvas.coords(items1[0])[:2]
                x2, y2 = self.topology_canvas.coords(items2[0])[:2]
                self.topology_canvas.create_line(x1, y1, x2, y2, fill="gray")
                
    def highlight_packet_path(self, packet, current_node):
        # Clear previous highlights
        for edge in self.network_topology.edges:
            device1, device2 = edge
            items1 = self.topology_canvas.find_withtag(device1)
            items2 = self.topology_canvas.find_withtag(device2)
            if items1 and items2:
                x1, y1 = self.topology_canvas.coords(items1[0])[:2]
                x2, y2 = self.topology_canvas.coords(items2[0])[:2]
                self.topology_canvas.create_line(x1, y1, x2, y2, fill="gray")

        # Highlight current path
        if current_node in packet.path:
            index = packet.path.index(current_node)
            if index > 0:
                prev_node = packet.path[index - 1]
                items1 = self.topology_canvas.find_withtag(prev_node)
                items2 = self.topology_canvas.find_withtag(current_node)
                if items1 and items2:
                    x1, y1 = self.topology_canvas.coords(items1[0])[:2]
                    x2, y2 = self.topology_canvas.coords(items2[0])[:2]
                    self.topology_canvas.create_line(x1, y1, x2, y2, fill="blue", width=2)
                    
    def on_close(self):
        plt.close('all')
        self.root.destroy()


if __name__ == "__main__":
    simulator = AdvancedNetworkSimulator()
    simulator.root.protocol("WM_DELETE_WINDOW", simulator.on_close)
    simulator.root.mainloop()