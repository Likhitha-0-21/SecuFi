from tkinter import *
from tkinter import messagebox
import subprocess
import random
from PIL import Image, ImageTk  # For handling images

def center_window(root):
    """ Centers the window and maximizes it """
    root.state("zoomed")

def shimmer_label(label, colors=["#585858", "white", "#585858"], delay=300):
    """ Creates a shimmering effect on the label text """
    def change_color():
        color = random.choice(colors)
        label.config(fg=color)
        label.after(delay, change_color)
    change_color()

def run_script(script_name):
    """ Runs an external script and displays the output """
    website = entry.get().strip()
    if not website:
        messagebox.showerror("Error", "Please enter a website URL.")
        return
    try:
        result = subprocess.run(["python", script_name, website], capture_output=True, text=True, check=True)
        output = result.stdout
        messagebox.showinfo(f"{script_name} Output", output)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Error running {script_name} script:\n{e.stderr}")

# Initialize GUI
root = Tk()
root.title("Enhancing Wireless Network Security with Real-Time Vulnerability Detection")
center_window(root)

# Load and Set Background Image
bg_image_path = r"background.png"
bg_image = Image.open(bg_image_path)
bg_image = bg_image.resize((root.winfo_screenwidth(), root.winfo_screenheight()))  # Resize to fit screen
bg_photo = ImageTk.PhotoImage(bg_image)

# Set the background
bg_label = Label(root, image=bg_photo)
bg_label.place(relwidth=1, relheight=1)  # Cover full window

# Transparent Frame
frame = Frame(root, bg="#bf96e9", bd=5, highlightthickness=0)
# Move the frame to the left side
frame.place(relx=0.2, rely=0.5, anchor=CENTER)


# Title Label (No solid background)
label = Label(frame, text="𝘞𝘪‑𝘍𝘪 𝘝𝘶𝘭𝘯𝘦𝘳𝘢𝘣𝘪𝘭𝘪𝘵𝘺 𝘋𝘦𝘵𝘦𝘤𝘵𝘰𝘳", font=("Arial", 30, "bold"), fg="white", bg="#bf96e9")
label.pack(pady=20)
shimmer_label(label)

# Input Field
entry_label = Label(frame, text="Enter website URL:", font=("Arial", 15), fg="white", bg="#bf96e9")
entry_label.pack()
entry = Entry(frame, font=("Arial", 16), width=30, highlightthickness=0, bd=2)
entry.pack(pady=10)

# Button Frame (transparent)
button_frame = Frame(frame,bg="#bf96e9")
button_frame.pack(pady=20)

button1 = Button(button_frame, text="Check DNS", font=("Arial", 16), fg="#585858", bg="white", activebackground="#a9b6ed", cursor="hand2",
                 command=lambda: run_script("DNS_Final.py"), borderwidth=0, highlightthickness=0)
button2 = Button(button_frame, text="Check ARP", font=("Arial", 16), fg="#585858", bg="white", activebackground="#a9b6ed", cursor="hand2",
                 command=lambda: run_script("ARP.py"), borderwidth=0, highlightthickness=0)
button3 = Button(button_frame, text="Check Sniffing", font=("Arial", 16), fg="#585858", bg="white", activebackground="#a9b6ed", cursor="hand2",
                 command=lambda: run_script("Sniffing.py"), borderwidth=0, highlightthickness=0)

button1.pack(side=LEFT, padx=10)
button2.pack(side=LEFT, padx=10)
button3.pack(side=LEFT, padx=10)

root.mainloop()