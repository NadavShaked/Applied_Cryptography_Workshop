# Standard library imports
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

# Third-party library imports
from enum import Enum

# Local imports
from PublicKeyVersionScheme.helpers import get_blocks_authenticators_by_file_path, p, MAC_SIZE, BLOCK_SIZE, generate_x, \
    generate_g, generate_v, generate_u, compress_g2_to_hex, compress_g1_to_hex
from Common.helpers import write_file_by_blocks_with_authenticators, write_file_by_blocks


class Page(Enum):
    ENCODING = "Encoding"
    DECODING = "Decoding"
    SOLANA = "Solana"


def encoding_select_file():
    file_path = filedialog.askopenfilename(title="Select a File")
    if file_path:
        file_path_to_encode_var.set(file_path)


def decoding_select_file():
    file_path = filedialog.askopenfilename(title="Select a File")
    if file_path:
        file_path_to_decode_var.set(file_path)


def generate_ecc_file():
    if not file_path_to_encode_var.get():
        messagebox.showwarning("Warning", "Please select a file first.")
        return

    save_path = filedialog.askdirectory(title="Select Destination Folder")

    if save_path:
        file_name = os.path.basename(file_path_to_encode_var.get())
        encoded_file_name: str = file_name + ".encoded"

        file_path = file_path_to_encode_var.get()
        encoded_file_path = os.path.join(save_path, encoded_file_name)
        try:
            x: int = generate_x() # private key

            g = generate_g()
            v = generate_v(g, x)  # v = g^x in G2

            u = generate_u()  # u in G1

            blocks_with_authenticators: list[tuple[bytes, bytes]] = get_blocks_authenticators_by_file_path(file_path,
                                                                                                           BLOCK_SIZE,
                                                                                                           p,
                                                                                                           x,
                                                                                                           u,
                                                                                                           MAC_SIZE)

            write_file_by_blocks_with_authenticators(encoded_file_path, blocks_with_authenticators)

            # Display values in the UI
            encoding_output_text.config(state=tk.NORMAL)
            encoding_output_text.delete("1.0", tk.END)
            encoding_output_text.insert(tk.END, f"x (private key): {x}\n")
            encoding_output_text.insert(tk.END, f"g: {compress_g2_to_hex(g)}\n")
            encoding_output_text.insert(tk.END, f"v (g^x in G2): {compress_g2_to_hex(v)}\n")
            encoding_output_text.insert(tk.END, f"u (in G1): {compress_g1_to_hex(u)}\n")
            encoding_output_text.config(state=tk.DISABLED)

            messagebox.showinfo("Success", f"ECC File copied to {encoded_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy file: {e}")


def decode_ecc_file():
    if not file_path_to_decode_var.get():
        messagebox.showwarning("Warning", "Please select a file first.")
        return

    save_path = filedialog.askdirectory(title="Select Destination Folder")

    if save_path:
        file_name = os.path.basename(file_path_to_decode_var.get())

        if not file_name.endswith(".encoded"):
            messagebox.showwarning("Warning", "Selected file must have a .encoded extension.")
            return

        decoded_file_name = file_name.removesuffix(".encoded")

        file_path = file_path_to_decode_var.get()
        decoded_file_path = os.path.join(save_path, decoded_file_name)
        try:
            _3d_mac_size: int = MAC_SIZE * 3

            blocks: list[bytes] = []

            # Calculate the σ and μ
            with open(file_path, "rb") as f:

                while True:
                    # Read the next block (data + authenticator)
                    full_block: bytes = f.read(
                        BLOCK_SIZE + _3d_mac_size)  # up-to 1024-byte data, 4-byte * 3 for 3d point authenticator tag
                    if not full_block:
                        break  # End of file

                    blocks.append(full_block[:-_3d_mac_size])

            write_file_by_blocks(decoded_file_path, blocks)

            messagebox.showinfo("Success", f"Decode file copied to {decoded_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy file: {e}")


def start_subscription():
    solana_output_text.config(state=tk.NORMAL)
    solana_output_text.delete("1.0", tk.END)
    public_key = my_public_key_var.get().strip()
    if not public_key:
        solana_output_text.insert(tk.END, "My public key is required\n")
    else:
        solana_output_text.insert(tk.END, f"{public_key}\n")
        escrow_public_key_var.set(public_key)
    solana_output_text.config(state=tk.DISABLED)


def add_funds_to_subscription():
    solana_output_text.config(state=tk.NORMAL)
    solana_output_text.delete("1.0", tk.END)

    public_key = my_public_key_var.get().strip()
    escrow_public_key = escrow_public_key_var.get().strip()
    sol_amount = sol_amount_var.get().strip()

    if not public_key:
        solana_output_text.insert(tk.END, "My public key is required\n")
    if not escrow_public_key:
        solana_output_text.insert(tk.END, "Escrow public key is required\n")
    if not sol_amount:
        solana_output_text.insert(tk.END, "SOL amount is required\n")

    if public_key and escrow_public_key and sol_amount:
        solana_output_text.insert(tk.END, "Success\n")

    solana_output_text.config(state=tk.DISABLED)


def end_subscription():
    solana_output_text.config(state=tk.NORMAL)
    solana_output_text.delete("1.0", tk.END)
    solana_output_text.insert(tk.END, "Success\n")
    solana_output_text.config(state=tk.DISABLED)


def update_content(option):
    # Update the selected option
    selected_option.set(option)

    # Clear the current content in the center panel
    for widget in content_frame.winfo_children():
        widget.destroy()

    # Update button colors based on the selected option
    for child in nav_frame.winfo_children():
        if isinstance(child, ttk.Button):
            if child.cget("text") == option:
                child.configure(style="Selected.TButton")  # Apply red style to the selected button
            else:
                child.configure(style="Rounded.TButton")  # Reset others to the default style

    if option == Page.ENCODING:
        content_title = tk.Label(content_frame, text=Page.ENCODING.value, font=("Helvetica", 18, "bold"), bg=content_background_color, fg="#000000")
        content_title.pack(pady=10)

        content_description = tk.Label(
            content_frame,
            text="Perform a full encoding and authentication.",
            wraplength=400,
            justify="center",
            bg=content_background_color,
            fg="#000000"
        )
        content_description.pack(pady=10)

        action_button = ttk.Button(content_frame, text="Select File To Encode", command=encoding_select_file, style="Rounded.TButton")
        action_button.pack(pady=20)

        file_path_label = tk.Label(content_frame, text="Selected File:", bg=content_background_color, fg="#000000")
        file_path_label.pack(pady=(10, 0))

        file_path_entry = ttk.Entry(content_frame, textvariable=file_path_to_encode_var, state="readonly", width=50)
        file_path_entry.pack(pady=5)

        save_copy_button = ttk.Button(content_frame, text="Generate ECC File", command=generate_ecc_file, style="Rounded.TButton")
        save_copy_button.pack(pady=10)

        global encoding_output_text
        encoding_output_text = tk.Text(content_frame, height=15, width=80, wrap=tk.WORD)
        encoding_output_text.pack(pady=10)
        encoding_output_text.config(state=tk.DISABLED)

    elif option == Page.DECODING:
        content_title = tk.Label(content_frame, text=Page.DECODING.value, font=("Helvetica", 18, "bold"), bg=content_background_color, fg="#000000")
        content_title.pack(pady=10)

        content_description = tk.Label(
            content_frame,
            text="Perform a full decoding.",
            wraplength=400,
            justify="center",
            bg=content_background_color,
            fg="#000000"
        )
        content_description.pack(pady=10)

        action_button = ttk.Button(content_frame, text="Select File To Decode", command=decoding_select_file, style="Rounded.TButton")
        action_button.pack(pady=20)

        file_path_label = tk.Label(content_frame, text="Selected ECC File:", bg=content_background_color, fg="#000000")
        file_path_label.pack(pady=(10, 0))

        file_path_entry = ttk.Entry(content_frame, textvariable=file_path_to_decode_var, state="readonly", width=50)
        file_path_entry.pack(pady=5)

        save_copy_button = ttk.Button(content_frame, text="Generate Decode File", command=decode_ecc_file, style="Rounded.TButton")
        save_copy_button.pack(pady=10)

    elif option == Page.SOLANA:

        content_title = tk.Label(content_frame, text=Page.SOLANA.value, font=("Helvetica", 18, "bold"),

                                 bg=content_background_color, fg="#000000")

        content_title.pack(pady=10)

        tk.Label(content_frame, text="My Public Key:", bg=content_background_color, fg="#000000").pack()

        ttk.Entry(content_frame, textvariable=my_public_key_var, width=50).pack(pady=5)

        tk.Label(content_frame, text="Escrow Public Key:", bg=content_background_color, fg="#000000").pack()

        ttk.Entry(content_frame, textvariable=escrow_public_key_var, width=50).pack(pady=5)

        # Added SOL amount to transfer text box

        tk.Label(content_frame, text="SOL Amount to Transfer:", bg=content_background_color, fg="#000000").pack()

        ttk.Entry(content_frame, textvariable=sol_amount_var, width=50).pack(pady=5)

        button_frame = tk.Frame(content_frame, bg=content_background_color)

        button_frame.pack(pady=5)

        ttk.Button(button_frame, text="Start Subscription", command=start_subscription, style="Rounded.TButton").pack(

            side=tk.LEFT, padx=5)

        ttk.Button(button_frame, text="Add Funds to Subscription", command=add_funds_to_subscription,

                   style="Rounded.TButton").pack(side=tk.LEFT, padx=5)

        ttk.Button(button_frame, text="End Subscription", command=end_subscription, style="Rounded.TButton").pack(

            side=tk.LEFT, padx=5)

        global solana_output_text

        solana_output_text = tk.Text(content_frame, height=10, width=80, wrap=tk.WORD)

        solana_output_text.pack(pady=10)

        solana_output_text.config(state=tk.DISABLED)


# Create main window
root = tk.Tk()
root.title("Crypto Course")
root.geometry("800x500")
root.resizable(False, False)

# Styling
nav_color = "#1c2c3c"
content_background_color = "#F5F5F5"
button_color = "#3475df"
text_color = "#FFFFFF"
default_font = ("Helvetica", 12)

# Remove button border and flat style
style = ttk.Style()
style.theme_use("clam")
style.configure("TFrame", background=content_background_color)
style.configure("TLabel", font=default_font, background=content_background_color, foreground=text_color)
style.configure("TButton", font=default_font, padding=6, background=button_color, foreground=text_color, borderwidth=0, relief="flat")
style.map("TButton",
          background=[("active", nav_color), ("!disabled", nav_color)],
          foreground=[("active", text_color), ("!disabled", text_color)])
style.configure("Rounded.TButton", font=default_font, padding=10, background=button_color, foreground=text_color, borderwidth=0, relief="flat", border=10)
style.configure("Selected.TButton", font=default_font, padding=10, background=nav_color, foreground=text_color, borderwidth=0, relief="flat", border=10)
style.map("Selected.TButton",
          background=[("active", button_color), ("!disabled", button_color)],
          foreground=[("active", text_color), ("!disabled", text_color)])

# Variable to store selected file path to encode
file_path_to_encode_var = tk.StringVar()

# Variable to store selected file path to decode
file_path_to_decode_var = tk.StringVar()

# Variable to track selected option
selected_option = tk.StringVar(value=Page.ENCODING)

# Variable to track my public key
my_public_key_var = tk.StringVar()

# Variable to track escrow public key
escrow_public_key_var = tk.StringVar()

# Variable to track SOL amount
sol_amount_var = tk.StringVar()

# Main layout
main_frame = ttk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=True)

# Left navigation panel
nav_frame = tk.Frame(main_frame, width=200, bg=nav_color)
nav_frame.pack(side=tk.LEFT, fill=tk.Y)

nav_label = tk.Label(nav_frame, text="Crypto Course", font=("Helvetica", 16, "bold"), bg=nav_color, fg=text_color, anchor="center")
nav_label.pack(pady=20)

# Menu options
menu_options = [Page.ENCODING, Page.DECODING, Page.SOLANA]
for option in menu_options:
    btn = ttk.Button(nav_frame, text=option.value, command=lambda opt=option: update_content(opt))
    btn.pack(fill=tk.X, pady=5, ipadx=10)  # Fill horizontally across the nav_frame

# Right content panel
content_frame = tk.Frame(main_frame, bg=content_background_color)
content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=20, pady=20)

# Initially load Encryption content
update_content(Page.ENCODING)

# Start GUI main loop
root.mainloop()
