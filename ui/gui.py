import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from tkinter import scrolledtext
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Querybox
from main import PDCP
from pdcp.compression import ROHCProfile, ROHCMode

class PDCPGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("PDCP Simulator")
        self.master.geometry("1024x1000")
        
        self.style = ttkb.Style(theme="darkly")
        
        self.pdcp = PDCP()
        self.pdcp.initialize_security(bearer=1, direction=0)

        self.create_widgets()

    def create_widgets(self):
        main_notebook = ttkb.Notebook(self.master)
        main_notebook.pack(fill=BOTH, expand=YES, padx=10, pady=10)

        self.create_simulation_tab(main_notebook)
        self.create_database_tab(main_notebook)
        self.create_settings_tab(main_notebook)

    def create_simulation_tab(self, notebook):
        sim_frame = ttkb.Frame(notebook)
        notebook.add(sim_frame, text="Simulation")

        # Input Frame
        input_frame = ttkb.LabelFrame(sim_frame, text="Input", padding=10)
        input_frame.pack(fill=X, padx=10, pady=10)

        ttkb.Label(input_frame, text="IP Packet (hex):").grid(row=0, column=0, padx=5, pady=5, sticky=W)
        self.ip_packet_entry = ttkb.Entry(input_frame, width=50)
        self.ip_packet_entry.grid(row=0, column=1, padx=5, pady=5)
        self.ip_packet_entry.insert(0, "4500003c1c46400040113c8fc0a80001c0a800c7")

        ttkb.Label(input_frame, text="SN Length:").grid(row=1, column=0, padx=5, pady=5, sticky=W)
        self.sn_length_var = tk.StringVar(value="12")
        ttkb.Radiobutton(input_frame, text="12", variable=self.sn_length_var, value="12").grid(row=1, column=1, padx=5, pady=5, sticky=W)
        ttkb.Radiobutton(input_frame, text="18", variable=self.sn_length_var, value="18").grid(row=1, column=2, padx=5, pady=5, sticky=W)

        # ROHC options
        ttkb.Label(input_frame, text="Profile:").grid(row=2, column=0, padx=5, pady=5, sticky=W)
        self.profile_var = tk.StringVar(value="UNCOMPRESSED")
        profile_combo = ttkb.Combobox(input_frame, textvariable=self.profile_var, values=["UNCOMPRESSED", "RTP", "UDP", "ESP", "IP"])
        profile_combo.grid(row=2, column=1, padx=5, pady=5)
        profile_combo.bind("<<ComboboxSelected>>", self.update_rohc_options)

        ttkb.Label(input_frame, text="Mode:").grid(row=3, column=0, padx=5, pady=5, sticky=W)
        self.mode_var = tk.StringVar(value="UNIDIRECTIONAL")
        mode_combo = ttkb.Combobox(input_frame, textvariable=self.mode_var, values=["UNIDIRECTIONAL", "BIDIRECTIONAL_OPTIMISTIC", "BIDIRECTIONAL_RELIABLE"])
        mode_combo.grid(row=3, column=1, padx=5, pady=5)
        mode_combo.bind("<<ComboboxSelected>>", self.update_rohc_options)

        # Buttons
        button_frame = ttkb.Frame(sim_frame)
        button_frame.pack(fill=X, padx=10, pady=10)

        ttkb.Button(button_frame, text="Process Packet", command=self.process_packet, bootstyle="success").pack(side=LEFT, padx=5)
        ttkb.Button(button_frame, text="Reset ROHC Context", command=self.reset_rohc_context, bootstyle="warning").pack(side=LEFT, padx=5)

        # Output
        output_frame = ttkb.LabelFrame(sim_frame, text="Output", padding=10)
        output_frame.pack(fill=BOTH, expand=YES, padx=10, pady=10)

        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=15)
        self.output_text.pack(fill=BOTH, expand=YES)

        # State Information
        state_frame = ttkb.LabelFrame(sim_frame, text="State Information", padding=10)
        state_frame.pack(fill=X, padx=10, pady=10)

        self.state_text = scrolledtext.ScrolledText(state_frame, wrap=tk.WORD, width=80, height=6)
        self.state_text.pack(fill=BOTH, expand=YES)

        self.update_state_info()

    def create_database_tab(self, notebook):
        db_frame = ttkb.Frame(notebook)
        notebook.add(db_frame, text="Database")

        ttkb.Button(db_frame, text="Show All PDUs", command=self.show_all_pdus, bootstyle="info").pack(pady=10)
        ttkb.Button(db_frame, text="Get PDU by SN", command=self.get_pdu_by_sn, bootstyle="info").pack(pady=10)

        self.db_output = scrolledtext.ScrolledText(db_frame, wrap=tk.WORD, width=80, height=20)
        self.db_output.pack(fill=BOTH, expand=YES, padx=10, pady=10)

    def create_settings_tab(self, notebook):
        settings_frame = ttkb.Frame(notebook)
        notebook.add(settings_frame, text="Settings")

        # Add settings controls here
        ttkb.Label(settings_frame, text="Bearer:").grid(row=0, column=0, padx=5, pady=5, sticky=W)
        self.bearer_var = tk.StringVar(value="1")
        ttkb.Entry(settings_frame, textvariable=self.bearer_var, width=10).grid(row=0, column=1, padx=5, pady=5)

        ttkb.Label(settings_frame, text="Direction:").grid(row=1, column=0, padx=5, pady=5, sticky=W)
        self.direction_var = tk.StringVar(value="0")
        ttkb.Radiobutton(settings_frame, text="Uplink (0)", variable=self.direction_var, value="0").grid(row=1, column=1, padx=5, pady=5)
        ttkb.Radiobutton(settings_frame, text="Downlink (1)", variable=self.direction_var, value="1").grid(row=1, column=2, padx=5, pady=5)

        ttkb.Button(settings_frame, text="Apply Settings", command=self.apply_settings, bootstyle="primary").grid(row=2, column=0, columnspan=3, pady=20)

    def update_rohc_options(self, event=None):
        profile = getattr(ROHCProfile, self.profile_var.get())
        mode = getattr(ROHCMode, self.mode_var.get())
        self.pdcp.set_rohc_profile(profile, mode)
        self.update_state_info()

    def reset_rohc_context(self):
        self.pdcp.reset_rohc_context()
        self.update_state_info()
        self.output_text.insert(tk.END, "ROHC context has been reset.\n")

    def process_packet(self):
        try:
            ip_packet = bytes.fromhex(self.ip_packet_entry.get())
            sn_length = int(self.sn_length_var.get())
            profile = getattr(ROHCProfile, self.profile_var.get())
            mode = getattr(ROHCMode, self.mode_var.get())

            pdcp_pdu = self.pdcp.process_packet(ip_packet, sn_length)
            received_ip_packet = self.pdcp.process_received_packet(pdcp_pdu, sn_length)

            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Original IP Packet: {ip_packet.hex()}\n\n")
            self.output_text.insert(tk.END, f"PDCP PDU: {pdcp_pdu.hex()}\n\n")
            self.output_text.insert(tk.END, f"Received IP Packet: {received_ip_packet.hex()}\n\n")

            if ip_packet == received_ip_packet:
                self.output_text.insert(tk.END, "Success: End-to-end processing completed successfully.", "success")
            else:
                self.output_text.insert(tk.END, "Error: End-to-end processing failed.", "error")

            self.output_text.tag_configure("success", foreground="green")
            self.output_text.tag_configure("error", foreground="red")

            self.update_state_info()
        except Exception as e:
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Error: {str(e)}", "error")

    def update_state_info(self):
        state_info = self.pdcp.get_state_info()
        self.state_text.delete(1.0, tk.END)
        for key, value in state_info.items():
            self.state_text.insert(tk.END, f"{key}: {value}\n")

    def show_all_pdus(self):
        pdus = self.pdcp.db.get_all_pdus()
        self.display_pdus(pdus)

    def get_pdu_by_sn(self):
        sn = Querybox.get_integer("Enter Sequence Number")
        if sn is not None:
            pdu = self.pdcp.db.get_pdu_by_sn(sn)
            if pdu:
                self.display_pdus([pdu])
            else:
                messagebox.showinfo("Info", f"No PDU found with SN {sn}")

    def display_pdus(self, pdus):
        self.db_output.delete(1.0, tk.END)
        for pdu in pdus:
            self.db_output.insert(tk.END, f"ID: {pdu[0]}\n")
            self.db_output.insert(tk.END, f"Timestamp: {pdu[1]}\n")
            self.db_output.insert(tk.END, f"Direction: {pdu[2]}\n")
            self.db_output.insert(tk.END, f"SN: {pdu[3]}\n")
            self.db_output.insert(tk.END, f"PDU Type: {pdu[4]}\n")
            self.db_output.insert(tk.END, f"PDU Data: {pdu[5].hex()}\n")
            self.db_output.insert(tk.END, f"Original IP Packet: {pdu[6].hex()}\n")
            self.db_output.insert(tk.END, "\n" + "-"*50 + "\n\n")

    def apply_settings(self):
        bearer = int(self.bearer_var.get())
        direction = int(self.direction_var.get())
        self.pdcp.initialize_security(bearer, direction)
        self.update_state_info()
        messagebox.showinfo("Settings Applied", f"Bearer set to {bearer}, Direction set to {'Downlink' if direction else 'Uplink'}")

    def __del__(self):
        self.pdcp.close()

if __name__ == "__main__":
    root = ttkb.Window(themename="darkly")
    gui = PDCPGUI(root)
    root.mainloop()