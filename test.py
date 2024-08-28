import requests
import vt 
import tkinter as tk
from tkinter import messagebox

# Replace with your actual VirusTotal API key
API_KEY = "fa7a680810a11723662329ae83346d6ac064c2c0dd0b12a600793ed97b571a7c"

def scan_url():
    url = url_entry.get()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL")
        return
    
    try:
        client = vt.Client(API_KEY)
        analysis = client.scan_url(url)
        scan_id = analysis.id  # Access the 'id' attribute instead of using subscript
        result_label.config(text=f"Scan ID: {scan_id}\nScanning...")
        root.after(2000, check_results, scan_id)  # Wait 2 seconds before checking results
    except vt.error.APIError as e:
        messagebox.showerror("API Error", f"VirusTotal API error: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")
    finally:
        client.close()

def check_results(scan_id):
    try:
        client = vt.Client(API_KEY)
        analysis = client.get_object(f"/analyses/{scan_id}")
        stats = analysis.stats
        result_text = (
            f"Malicious: {stats['malicious']}\n"
            f"Suspicious: {stats['suspicious']}\n"
            f"Undetected: {stats['undetected']}\n"
            f"Timeout: {stats['timeout']}\n"
        )
        result_label.config(text=result_text)
    except vt.error.APIError as e:
        messagebox.showerror("API Error", f"VirusTotal API error: {e}")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")
    finally:
        client.close()

# Setting up the Tkinter window
root = tk.Tk()
root.title("VirusTotal URL Scanner")

tk.Label(root, text="Enter URL:").pack(pady=10)
url_entry = tk.Entry(root, width=50)
url_entry.pack(pady=5)

scan_button = tk.Button(root, text="Scan URL", command=scan_url)
scan_button.pack(pady=20)

result_label = tk.Label(root, text="", wraplength=400)
result_label.pack(pady=10)

# Start the Tkinter event loop
root.mainloop()