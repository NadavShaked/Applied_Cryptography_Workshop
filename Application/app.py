# Standard library imports
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

# Third-party library imports
from enum import Enum
from PIL import ImageTk, Image

# Local imports
from PublicKeyVersionScheme.helpers import get_blocks_authenticators_by_file_path, p, MAC_SIZE, BLOCK_SIZE, generate_x, \
    generate_g, generate_v, generate_u, compress_g2_to_hex, compress_g1_to_hex
from Common.helpers import write_file_by_blocks_with_authenticators, write_file_by_blocks


class Page(Enum):
    ENCODING = "Encoding"
    DECODING = "Decoding"
    SOLANA = "Solana"


class Solana_Page(Enum):
    START_SUBSCRIPTION = "Start Subscription"
    ADD_FUNDS_TO_SUBSCRIPTION = "Add Funds To Subscription"
    END_SUBSCRIPTION = "End Subscription"
    REQUEST_FUNDS = "Request Funds"


solana_start_subscription_output_text_value = ""
solana_add_funds_to_subscription_output_text_value = ""
solana_end_subscription_output_text_value = ""
solana_request_funds_output_text_value = ""


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
    global solana_start_subscription_output_text_value

    my_public_key = start_subscription_frame_my_public_key_var.get().strip()
    seller_public_key = start_subscription_frame_seller_public_key_var.get().strip()
    u = start_subscription_frame_u_var.get().strip()
    g = start_subscription_frame_g_var.get().strip()
    v = start_subscription_frame_v_var.get().strip()
    query_size = start_subscription_frame_query_size_var.get().strip()
    blocks_number = start_subscription_frame_blocks_number_var.get().strip()
    validate_every = start_subscription_frame_validate_every_var.get().strip()

    solana_start_subscription_output_text.config(state=tk.NORMAL)
    solana_start_subscription_output_text.delete("1.0", tk.END)

    if not my_public_key:
        solana_start_subscription_output_text.insert(tk.END, "My public key is required\n")
    if not seller_public_key:
        solana_start_subscription_output_text.insert(tk.END, "Seller public key is required\n")
    if not u:
        solana_start_subscription_output_text.insert(tk.END, "u - G1 point is required\n")
    if not g:
        solana_start_subscription_output_text.insert(tk.END, "g - G2 point is required\n")
    if not v:
        solana_start_subscription_output_text.insert(tk.END, "v - G2 point is required\n")
    if not query_size:
        solana_start_subscription_output_text.insert(tk.END, "Query size is required\n")
    if not blocks_number:
        solana_start_subscription_output_text.insert(tk.END, "Block number is required\n")
    if not validate_every:
        solana_start_subscription_output_text.insert(tk.END, "Validate every is required\n")
    else:
        solana_start_subscription_output_text.insert(tk.END, f"Escrow public key: {my_public_key}\n")

    solana_start_subscription_output_text_value = solana_start_subscription_output_text.get("1.0", tk.END)
    solana_start_subscription_output_text.config(state=tk.DISABLED)


def add_funds_to_subscription():
    global solana_add_funds_to_subscription_output_text_value

    public_key = add_funds_to_subscription_frame_my_public_key_var.get().strip()
    escrow_public_key = add_funds_to_subscription_frame_escrow_public_key_var.get().strip()
    sol_amount = add_funds_to_subscription_frame_sol_amount_var.get().strip()

    solana_add_funds_to_subscription_output_text.config(state=tk.NORMAL)
    solana_add_funds_to_subscription_output_text.delete("1.0", tk.END)

    if not public_key:
        solana_add_funds_to_subscription_output_text.insert(tk.END, "My public key is required\n")
    if not escrow_public_key:
        solana_add_funds_to_subscription_output_text.insert(tk.END, "Escrow public key is required\n")
    if not sol_amount:
        solana_add_funds_to_subscription_output_text.insert(tk.END, "SOL amount is required\n")

    if public_key and escrow_public_key and sol_amount:
        solana_add_funds_to_subscription_output_text.insert(tk.END, "Success\n")

    solana_add_funds_to_subscription_output_text_value = solana_add_funds_to_subscription_output_text.get("1.0", tk.END)
    solana_add_funds_to_subscription_output_text.config(state=tk.DISABLED)


def end_subscription():
    global solana_end_subscription_output_text_value

    public_key = end_subscription_frame_my_public_key_var.get().strip()
    escrow_public_key = end_subscription_frame_escrow_public_key_var.get().strip()

    solana_end_subscription_output_text.config(state=tk.NORMAL)
    solana_end_subscription_output_text.delete("1.0", tk.END)

    if not public_key:
        solana_end_subscription_output_text.insert(tk.END, "My public key is required\n")
    if not escrow_public_key:
        solana_end_subscription_output_text.insert(tk.END, "Escrow public key is required\n")

    if public_key and escrow_public_key:
        solana_end_subscription_output_text.insert(tk.END, "Success\n")

    solana_end_subscription_output_text_value = solana_end_subscription_output_text.get("1.0", tk.END)
    solana_end_subscription_output_text.config(state=tk.DISABLED)  # Disable it again


def request_funds():
    global solana_request_funds_output_text_value

    public_key = start_subscription_frame_my_public_key_var.get().strip()

    solana_request_funds_output_text.config(state=tk.NORMAL)
    solana_request_funds_output_text.delete("1.0", tk.END)

    if not public_key:
        solana_request_funds_output_text.insert(tk.END, "My public key is required\n")
    else:
        solana_request_funds_output_text.insert(tk.END, f"{public_key}\n")
        request_funds_frame_escrow_public_key_var.set(public_key)

    solana_request_funds_output_text_value = solana_request_funds_output_text.get("1.0", tk.END)
    solana_request_funds_output_text.config(state=tk.DISABLED)


def update_solana_content(button_frame, selected_solana_page_option):
    # Clear the current content in the solana_content_frame
    for widget in solana_content_frame.winfo_children():
        widget.destroy()

    # Update button colors based on the selected option
    for child in button_frame.winfo_children():
        if isinstance(child, ttk.Button):
            if child.cget("text") == selected_solana_page_option.value:
                child.configure(style="Selected.TButton")
            else:
                child.configure(style="Rounded.TButton")

    if selected_solana_page_option == Solana_Page.START_SUBSCRIPTION:
        # Add content for "Start Subscription"
        tk.Label(solana_content_frame, text="Buyer Account:", bg=content_background_color, fg="#000000").pack()
        ttk.Entry(solana_content_frame, textvariable=start_subscription_frame_my_public_key_var, width=50).pack(pady=5)

        tk.Label(solana_content_frame, text="Seller Account:", bg=content_background_color, fg="#000000").pack()
        ttk.Entry(solana_content_frame, textvariable=start_subscription_frame_seller_public_key_var, width=50).pack(pady=5)

        # Create a frame for aligned inputs
        param_frame = tk.Frame(solana_content_frame, bg=content_background_color)
        param_frame.pack(pady=5)

        # First row: u, g, v
        tk.Label(param_frame, text="u:", bg=content_background_color, fg="#000000").grid(row=0, column=0, padx=5)
        ttk.Entry(param_frame, textvariable=start_subscription_frame_u_var, width=15).grid(row=0, column=1, padx=5)

        tk.Label(param_frame, text="g:", bg=content_background_color, fg="#000000").grid(row=1, column=0, padx=5)
        ttk.Entry(param_frame, textvariable=start_subscription_frame_g_var, width=15).grid(row=1, column=1, padx=5)

        tk.Label(param_frame, text="v:", bg=content_background_color, fg="#000000").grid(row=2, column=0, padx=5)
        ttk.Entry(param_frame, textvariable=start_subscription_frame_v_var, width=15).grid(row=2, column=1, padx=5)

        # Second row: query_size, blocks_number, validate_every
        tk.Label(param_frame, text="Query Size:", bg=content_background_color, fg="#000000").grid(row=0, column=2,
                                                                                                  padx=5)
        ttk.Entry(param_frame, textvariable=start_subscription_frame_query_size_var, width=15).grid(row=0, column=3,
                                                                                                    padx=5)

        tk.Label(param_frame, text="Blocks Number:", bg=content_background_color, fg="#000000").grid(row=1, column=2,
                                                                                                     padx=5)
        ttk.Entry(param_frame, textvariable=start_subscription_frame_blocks_number_var, width=15).grid(row=1, column=3,
                                                                                                       padx=5)

        tk.Label(param_frame, text="Validate Every:", bg=content_background_color, fg="#000000").grid(row=2, column=2,
                                                                                                      padx=5)
        ttk.Entry(param_frame, textvariable=start_subscription_frame_validate_every_var, width=15).grid(row=2, column=3,
                                                                                                        padx=5)

        # Button to start the subscription
        ttk.Button(solana_content_frame, text="Send Request to Solana", command=start_subscription,
                   style="Rounded.TButton").pack(pady=5)

        global solana_start_subscription_output_text
        solana_start_subscription_output_text = tk.Text(solana_content_frame, height=15, width=80, wrap=tk.WORD)
        solana_start_subscription_output_text.pack(pady=10)
        solana_start_subscription_output_text.config(state=tk.DISABLED)

        if solana_start_subscription_output_text_value:
            solana_start_subscription_output_text.config(state=tk.NORMAL)
            solana_start_subscription_output_text.insert(tk.END, solana_start_subscription_output_text_value)
            solana_start_subscription_output_text.config(state=tk.DISABLED)

    elif selected_solana_page_option == Solana_Page.ADD_FUNDS_TO_SUBSCRIPTION:
        # Add content for "Add Funds to Subscription"
        tk.Label(solana_content_frame, text="My Public Key:", bg=content_background_color, fg="#000000").pack()
        ttk.Entry(solana_content_frame, textvariable=add_funds_to_subscription_frame_my_public_key_var, width=50).pack(pady=5)

        tk.Label(solana_content_frame, text="Escrow Public Key:", bg=content_background_color, fg="#000000").pack()
        ttk.Entry(solana_content_frame, textvariable=add_funds_to_subscription_frame_escrow_public_key_var, width=50).pack(pady=5)

        tk.Label(solana_content_frame, text="SOL Amount to Add:", bg=content_background_color, fg="#000000").pack()
        ttk.Entry(solana_content_frame, textvariable=add_funds_to_subscription_frame_sol_amount_var, width=50).pack(pady=5)

        # Button to add funds to the subscription
        ttk.Button(solana_content_frame, text="Send Request to Solana", command=add_funds_to_subscription, style="Rounded.TButton").pack(pady=5)

        global solana_add_funds_to_subscription_output_text
        solana_add_funds_to_subscription_output_text = tk.Text(solana_content_frame, height=15, width=80, wrap=tk.WORD)
        solana_add_funds_to_subscription_output_text.pack(pady=10)
        solana_add_funds_to_subscription_output_text.config(state=tk.DISABLED)

        if solana_add_funds_to_subscription_output_text_value:
            solana_add_funds_to_subscription_output_text.config(state=tk.NORMAL)
            solana_add_funds_to_subscription_output_text.insert(tk.END, solana_add_funds_to_subscription_output_text_value)
            solana_add_funds_to_subscription_output_text.config(state=tk.DISABLED)

    elif selected_solana_page_option == Solana_Page.END_SUBSCRIPTION:
        tk.Label(solana_content_frame, text="My Public Key:", bg=content_background_color, fg="#000000").pack()
        ttk.Entry(solana_content_frame, textvariable=end_subscription_frame_my_public_key_var, width=50).pack(pady=5)

        tk.Label(solana_content_frame, text="Escrow Public Key:", bg=content_background_color, fg="#000000").pack()
        ttk.Entry(solana_content_frame, textvariable=end_subscription_frame_escrow_public_key_var, width=50).pack(
            pady=5)

        # Button to end the subscription
        ttk.Button(solana_content_frame, text="Send request to Solana", command=end_subscription,
                   style="Rounded.TButton").pack(pady=5)

        global solana_end_subscription_output_text

        solana_end_subscription_output_text = tk.Text(solana_content_frame, height=15, width=80, wrap=tk.WORD)
        solana_end_subscription_output_text.pack(pady=10)
        solana_end_subscription_output_text.config(state=tk.DISABLED)

        if solana_end_subscription_output_text_value:
            solana_end_subscription_output_text.config(state=tk.NORMAL)
            solana_end_subscription_output_text.insert(tk.END, solana_end_subscription_output_text_value)
            solana_end_subscription_output_text.config(state=tk.DISABLED)

    elif selected_solana_page_option == Solana_Page.REQUEST_FUNDS:
        tk.Label(solana_content_frame, text="My Public Key:", bg=content_background_color, fg="#000000").pack()
        ttk.Entry(solana_content_frame, textvariable=request_funds_frame_my_public_key_var, width=50).pack(pady=5)

        tk.Label(solana_content_frame, text="Escrow Public Key:", bg=content_background_color, fg="#000000").pack()
        ttk.Entry(solana_content_frame, textvariable=request_funds_frame_escrow_public_key_var, width=50).pack(pady=5)

        # Button to end the subscription
        ttk.Button(solana_content_frame, text="Send request to Solana", command=request_funds, style="Rounded.TButton").pack(pady=5)

        global solana_request_funds_output_text
        solana_request_funds_output_text = tk.Text(solana_content_frame, height=15, width=80, wrap=tk.WORD)
        solana_request_funds_output_text.pack(pady=10)
        solana_request_funds_output_text.config(state=tk.DISABLED)

        if solana_request_funds_output_text_value:
            solana_request_funds_output_text.config(state=tk.NORMAL)
            solana_request_funds_output_text.insert(tk.END, solana_request_funds_output_text_value)
            solana_request_funds_output_text.config(state=tk.DISABLED)


def update_content(option):
    # Clear the current content in the center panel
    for widget in content_frame.winfo_children():
        widget.destroy()

    # Update button colors based on the selected option
    for child in nav_frame.winfo_children():
        if isinstance(child, ttk.Button):
            if child.cget("text") == option.value:
                child.configure(style="Selected.TButton")
            else:
                child.configure(style="Rounded.TButton")

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

    # In the Solana page, create the frame that will change its content
    if option == Page.SOLANA:
        content_title = tk.Label(content_frame, text=Page.SOLANA.value, font=("Helvetica", 18, "bold"),
                                 bg=content_background_color, fg="#000000")
        content_title.pack(pady=10)

        # Button frame for the buttons (Start Subscription, Add Funds, End Subscription)
        button_frame = tk.Frame(content_frame, bg=content_background_color)
        button_frame.pack(pady=5)

        solana_page_options = [Solana_Page.START_SUBSCRIPTION, Solana_Page.ADD_FUNDS_TO_SUBSCRIPTION, Solana_Page.END_SUBSCRIPTION, Solana_Page.REQUEST_FUNDS]
        for solana_page_option in solana_page_options:
            ttk.Button(button_frame, text=solana_page_option.value,
                       command=lambda opt=solana_page_option: update_solana_content(button_frame, opt),
                       style="Rounded.TButton").pack(side=tk.LEFT, padx=5)

        global solana_content_frame
        # Create a new frame below the buttons for dynamic content
        solana_content_frame = tk.Frame(content_frame, bg=content_background_color)
        solana_content_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        # Set initial content for "Start Subscription"
        update_solana_content(button_frame, Solana_Page.START_SUBSCRIPTION)


# Create main window
root = tk.Tk()
root.title("Crypto Course")
root.geometry("800x500")
root.resizable(False, False)
icon_image = Image.open(
    './Application/solana-sol-logo.ico')
icon = ImageTk.PhotoImage(icon_image)
root.iconphoto(True, icon)

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

# Solana - Start subscription frame
# Variable to track my public key in start subscription frame
start_subscription_frame_my_public_key_var = tk.StringVar()
# Variable to track seller public key in start subscription frame
start_subscription_frame_seller_public_key_var = tk.StringVar()
# Variable to track u - G2 point value in start subscription frame
start_subscription_frame_u_var = tk.StringVar()
# Variable to track g - G2 point value in start subscription frame
start_subscription_frame_g_var = tk.StringVar()
# Variable to track v - G2 point value in start subscription frame
start_subscription_frame_v_var = tk.StringVar()
# Variable to track query size in start subscription frame
start_subscription_frame_query_size_var = tk.StringVar()
# Variable to track block number in start subscription frame
start_subscription_frame_blocks_number_var = tk.StringVar()
# Variable to track validate every in start subscription frame
start_subscription_frame_validate_every_var = tk.StringVar()

# Solana - Add fund to subscription frame
# Variable to track my public key in add fund to subscription frame
add_funds_to_subscription_frame_my_public_key_var = tk.StringVar()
# Variable to track my public key in add fund to subscription frame
add_funds_to_subscription_frame_escrow_public_key_var = tk.StringVar()
# Variable to track SOL amount
add_funds_to_subscription_frame_sol_amount_var = tk.StringVar()

# Solana - End subscription frame
# Variable to track my public key in end subscription frame
end_subscription_frame_my_public_key_var = tk.StringVar()
# Variable to track my public key in end subscription frame
end_subscription_frame_escrow_public_key_var = tk.StringVar()

# Solana - Request funds frame
# Variable to track my public key in request funds frame
request_funds_frame_my_public_key_var = tk.StringVar()
# Variable to track my public key in request funds frame
request_funds_frame_escrow_public_key_var = tk.StringVar()

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
