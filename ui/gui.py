# gui.py

import tkinter as tk
from tkinter import ttk, scrolledtext
from main import pdcp

class PDCPGUI:
    def __init__(self, master):
        self.master = master
        master.title("5G PDCP Simulator")
        master.geometry("800x600")

        self.create_widgets()

    def create_widgets(self):
        # Input frame
        input_frame = ttk.LabelFrame(self.master, text="Input")
        input_frame.pack(padx=10, pady=10, fill=tk.X)

        ttk.Label(input_frame, text="IP Packet (hex):").pack(side=tk.LEFT, padx=5)
        self.ip_packet_entry = ttk.Entry(input_frame, width=50)
        self.ip_packet_entry.pack(side=tk.LEFT, padx=5)
        self.ip_packet_entry.insert(0, "4500003c1c46400040113c8fc0a80001c0a800c7")

        ttk.Label(input_frame, text="SN Length:").pack(side=tk.LEFT, padx=5)
        self.sn_length_var = tk.StringVar(value="12")
        ttk.Radiobutton(input_frame, text="12", variable=self.sn_length_var, value="12").pack(side=tk.LEFT)
        ttk.Radiobutton(input_frame, text="18", variable=self.sn_length_var, value="18").pack(side=tk.LEFT)

        # Process button
        ttk.Button(self.master, text="Process Packet", command=self.process_packet).pack(pady=10)

        # Output frame
        output_frame = ttk.LabelFrame(self.master, text="Output")
        output_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=80, height=20)
        self.output_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # State info frame
        state_frame = ttk.LabelFrame(self.master, text="State Information")
        state_frame.pack(padx=10, pady=10, fill=tk.X)

        self.state_text = scrolledtext.ScrolledText(state_frame, wrap=tk.WORD, width=80, height=6)
        self.state_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        self.update_state_info()

    def process_packet(self):
        try:
            ip_packet = bytes.fromhex(self.ip_packet_entry.get())
            sn_length = int(self.sn_length_var.get())

            pdcp_pdu = pdcp.process_packet(ip_packet, sn_length)
            received_ip_packet = pdcp.process_received_packet(pdcp_pdu, sn_length)

            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Original IP Packet: {ip_packet.hex()}\n\n")
            self.output_text.insert(tk.END, f"PDCP PDU: {pdcp_pdu.hex()}\n\n")
            self.output_text.insert(tk.END, f"Received IP Packet: {received_ip_packet.hex()}\n\n")

            if ip_packet == received_ip_packet:
                self.output_text.insert(tk.END, "Success: End-to-end processing completed successfully.")
            else:
                self.output_text.insert(tk.END, "Error: End-to-end processing failed.")

            self.update_state_info()

        except Exception as e:
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"Error: {str(e)}")

    def update_state_info(self):
        state_info = pdcp.get_state_info()
        self.state_text.delete(1.0, tk.END)
        for key, value in state_info.items():
            self.state_text.insert(tk.END, f"{key}: {value}\n")

if __name__ == "__main__":
    root = tk.Tk()
    gui = PDCPGUI(root)
    root.mainloop()