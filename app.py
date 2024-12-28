import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk


def select_file():
    file_path = filedialog.askopenfilename(title="Select a File")
    if file_path:
        file_path_var.set(file_path)


def save_copy():
    if not file_path_var.get():
        messagebox.showwarning("Warning", "Please select a file first.")
        return

    save_path = filedialog.askdirectory(title="Select Destination Folder")
    if save_path:
        file_name = os.path.basename(file_path_var.get())
        destination = os.path.join(save_path, file_name)
        try:
            shutil.copy(file_path_var.get(), destination)
            messagebox.showinfo("Success", f"File copied to {destination}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy file: {e}")


def generate_ecc():
    if not file_path_var.get():
        messagebox.showwarning("Warning", "Please select a file first.")
        return

    ecc_file_name = os.path.basename(file_path_var.get()) + ".ecc"
    ecc_content = "Error Correcting Code (Placeholder Content)\n"  # Mock ECC content
    save_path = filedialog.askdirectory(title="Select Destination Folder")
    if save_path:
        ecc_file_path = os.path.join(save_path, ecc_file_name)
        try:
            with open(ecc_file_path, 'w') as ecc_file:
                ecc_file.write(ecc_content)
            messagebox.showinfo("Success", f"ECC file generated: {ecc_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate ECC file: {e}")


def decrypt_ecc():
    if not file_path_var.get():
        messagebox.showwarning("Warning", "Please select an ECC file first.")
        return

    decrypted_content = "Decrypted ECC Content (Placeholder)\n"  # Mock decrypted content
    save_path = filedialog.askdirectory(title="Select Destination Folder")
    if save_path:
        decrypted_file_name = os.path.basename(file_path_var.get()) + ".decrypted"
        decrypted_file_path = os.path.join(save_path, decrypted_file_name)
        try:
            with open(decrypted_file_path, 'w') as decrypted_file:
                decrypted_file.write(decrypted_content)
            messagebox.showinfo("Success", f"ECC file decrypted: {decrypted_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt ECC file: {e}")


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

    if option == "Full Scan":
        content_title = tk.Label(content_frame, text="Full Scan", font=("Helvetica", 18, "bold"), bg=content_background_color, fg="#000000")
        content_title.pack(pady=10)

        content_description = tk.Label(
            content_frame,
            text="Perform a full scan of your system.",
            wraplength=400,
            justify="center",
            bg=content_background_color,
            fg="#000000"
        )
        content_description.pack(pady=10)

        action_button = ttk.Button(content_frame, text="Start Full Scan", command=select_file, style="Rounded.TButton")
        action_button.pack(pady=20)

        file_path_label = tk.Label(content_frame, text="Selected File:", bg=content_background_color, fg="#000000")
        file_path_label.pack(pady=(10, 0))

        file_path_entry = ttk.Entry(content_frame, textvariable=file_path_var, state="readonly", width=50)
        file_path_entry.pack(pady=5)

        save_copy_button = ttk.Button(content_frame, text="Save a Copy", command=save_copy, style="Rounded.TButton")
        save_copy_button.pack(pady=10)

        generate_ecc_button = ttk.Button(content_frame, text="Generate ECC File", command=generate_ecc, style="Rounded.TButton")
        generate_ecc_button.pack(pady=10)

    elif option == "Antivirus":
        content_title = tk.Label(content_frame, text="Antivirus", font=("Helvetica", 18, "bold"), bg=content_background_color, fg="#000000")
        content_title.pack(pady=10)

        content_description = tk.Label(
            content_frame,
            text="Scan and remove potential threats from your system.",
            wraplength=400,
            justify="center",
            bg=content_background_color,
            fg="#000000"
        )
        content_description.pack(pady=10)

        action_button = ttk.Button(content_frame, text="Start Antivirus Scan", command=select_file, style="Rounded.TButton")
        action_button.pack(pady=20)

        file_path_label = tk.Label(content_frame, text="Selected ECC File:", bg=content_background_color, fg="#000000")
        file_path_label.pack(pady=(10, 0))

        file_path_entry = ttk.Entry(content_frame, textvariable=file_path_var, state="readonly", width=50)
        file_path_entry.pack(pady=5)

        save_copy_button = ttk.Button(content_frame, text="Save a Copy", command=save_copy, style="Rounded.TButton")
        save_copy_button.pack(pady=10)

        decrypt_ecc_button = ttk.Button(content_frame, text="Decrypt ECC File", command=decrypt_ecc, style="Rounded.TButton")
        decrypt_ecc_button.pack(pady=10)


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

# Variable to store selected file path
file_path_var = tk.StringVar()

# Variable to track selected option
selected_option = tk.StringVar(value="Full Scan")

# Main layout
main_frame = ttk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=True)

# Left navigation panel
nav_frame = tk.Frame(main_frame, width=200, bg=nav_color)
nav_frame.pack(side=tk.LEFT, fill=tk.Y)

nav_label = tk.Label(nav_frame, text="Crypto Course", font=("Helvetica", 16, "bold"), bg=nav_color, fg=text_color, anchor="center")
nav_label.pack(pady=20)

# Menu options
menu_options = ["Full Scan", "Antivirus"]
for option in menu_options:
    btn = ttk.Button(nav_frame, text=option, command=lambda opt=option: update_content(opt))
    btn.pack(fill=tk.X, pady=5, ipadx=10)  # Fill horizontally across the nav_frame

# Right content panel
content_frame = tk.Frame(main_frame, bg=content_background_color)
content_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=20, pady=20)

# Initially load Full Scan content
update_content("Full Scan")

# Start GUI main loop
root.mainloop()
