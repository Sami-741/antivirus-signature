import hashlib
import requests
import ttkbootstrap as ttk
from tkinter import messagebox, filedialog
from ttkbootstrap.constants import *
from PIL import Image, ImageTk
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import os
import threading
import shutil
import logging


logging.basicConfig(filename='antivirus.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

malicious_hashes = {}
VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
quarantine_folder = "quarantine"
uploads_folder = "uploads"

os.makedirs(quarantine_folder, exist_ok=True)
os.makedirs(uploads_folder, exist_ok=True)

def notify_user(title, message):
    messagebox.showinfo(title, message)

def check_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            hash_value = hashlib.md5(f.read()).hexdigest()
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        notify_user("Error", f"Error reading file: {e}")
        return

    if hash_value in malicious_hashes:
        handle_malicious_file(file_path)
    else:
        heuristic_result = heuristic_scan(file_path)
        if heuristic_result:
            notify_user("Warning", f"File '{file_path}' may be suspicious based on heuristic analysis.")
            handle_suspicious_file(file_path)
        else:
            cloud_result = cloud_scan(hash_value)
            notify_user("Info", f"File '{file_path}' is {'clean' if cloud_result else 'malicious'} according to cloud scan.")

def handle_malicious_file(file_path):
    action = messagebox.askquestion("Malicious File Detected", f"File is malicious. What would you like to do?", icon='warning', type='yesnocancel')
    if action == 'yes':
        quarantine_file(file_path)
    elif action == 'no':
        delete_file(file_path)

def handle_suspicious_file(file_path):
    action = messagebox.askquestion("Suspicious File Detected", f"File '{file_path}' is suspicious. What would you like to do?", icon='warning', type='yesnocancel')
    if action == 'yes':
        quarantine_file(file_path)
    elif action == 'no':
        notify_user("Info", "The file has been ignored.")

def quarantine_file(file_path):
    try:
        shutil.move(file_path, os.path.join(quarantine_folder, os.path.basename(file_path)))
        notify_user("Info", f"File '{file_path}' has been moved to quarantine.")
        logging.info(f"File '{file_path}' quarantined.")
    except Exception as e:
        logging.error(f"Failed to quarantine file: {e}")
        notify_user("Error", f"Failed to quarantine file: {e}")

def delete_file(file_path):
    try:
        os.remove(file_path)
        notify_user("Info", f"File '{file_path}' has been deleted.")
        logging.info(f"File '{file_path}' deleted.")
    except Exception as e:
        logging.error(f"Failed to delete file: {e}")
        notify_user("Error", f"Failed to delete file: {e}")

def cloud_scan(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        positives = response.json()['data']['attributes']['last_analysis_stats']['malicious']
        return positives == 0
    except requests.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err} - Status code: {response.status_code}")
        notify_user("Error", f"HTTP error occurred: {http_err}")
        return False
    except requests.ConnectionError:
        logging.error("Connection error occurred while trying to reach VirusTotal.")
        notify_user("Error", "Connection error occurred while trying to reach VirusTotal.")
        return False
    except requests.Timeout:
        logging.error("Request to VirusTotal timed out.")
        notify_user("Error", "Request to VirusTotal timed out.")
        return False
    except requests.RequestException as e:
        logging.error(f"Error retrieving results from VirusTotal: {e}")
        notify_user("Error", "Failed to retrieve results from VirusTotal.")
        return False

def heuristic_scan(file_path):
    try:
        file_size = os.path.getsize(file_path)
        if file_size > 5 * 1024 * 1024:
            return True
        _, ext = os.path.splitext(file_path)
        if ext.lower() in ['.exe', '.scr', '.bat', '.js', '.vbs']:
            return True
    except Exception as e:
        logging.error(f"An error occurred during heuristic scanning: {e}")
        notify_user("Error", f"An error occurred during heuristic scanning: {e}")
    return False

def update_hashes_periodically(interval=3600):
    while True:
        time.sleep(interval)

class Watcher:
    def __init__(self, directory):
        self.DIRECTORY_TO_WATCH = directory
        self.observer = Observer()

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.DIRECTORY_TO_WATCH, recursive=False)
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

class Handler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            check_file(event.src_path)

def on_submit():
    file_path = entry_filename.get()
    if not file_path:
        notify_user("Input Error", "Please enter a filename.")
        return
    check_file(file_path)

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_filename.delete(0, 'end')
        entry_filename.insert(0, file_path)

hash_update_thread = threading.Thread(target=update_hashes_periodically, daemon=True)
hash_update_thread.start()
root = ttk.Window(themename='darkly')
root.title("Antivirus Signature INSA")
root.geometry("1000x400")

image_path = "images/photo_2024-10-05_11-05-04.jpg"
try:
    image = Image.open(image_path)
    image = image.resize((1500, 400))
    photo = ImageTk.PhotoImage(image)

    canvas = ttk.Canvas(root, width=image.width, height=image.height)
    canvas.pack(fill="both", expand=True)
    canvas.create_image(0, 0, image=photo, anchor="nw")
except Exception as e:
    logging.error(f"Error loading image: {e}")
    notify_user("Error", "Failed to load image.")

label_filename = ttk.Label(root, text="Enter the filename to check:", font=("Helvetica", 14), bootstyle="light")
label_filename.pack(pady=10)

entry_filename = ttk.Entry(root, width=50, font=("Helvetica", 12), bootstyle="info")
entry_filename.pack(pady=5)

button_submit = ttk.Button(root, text="Check File", command=on_submit, bootstyle="primary")
button_submit.pack(pady=20)

button_browse = ttk.Button(root, text="Browse", command=browse_file, bootstyle="success")
button_browse.pack(pady=5)

directory_to_watch = filedialog.askdirectory(title="Select Directory to Monitor")
if directory_to_watch:
    watcher = Watcher(directory_to_watch)
    threading.Thread(target=watcher.run, daemon=True).start()

root.mainloop()
