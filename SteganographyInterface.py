import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk, ImageDraw, ImageFont

class SteganographyInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("Stenography Interface")

        # Crearea unui frame principal
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configurarea grilei
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Adăugarea de elemente UI
        self.add_widgets()

    def add_widgets(self):
        # Frame pentru butoanele și câmpurile de text
        control_frame = ttk.Frame(self.main_frame, padding="10")
        control_frame.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))

        # Butonul pentru alegerea imaginii
        choose_image_button = ttk.Button(control_frame, text="Alege Imagine", command=self.load_image)
        choose_image_button.grid(row=0, column=0, padx=5, pady=5)

        # Butonul pentru alegerea textului
        choose_text_button = ttk.Button(control_frame, text="Alege Text", command=self.load_text)
        choose_text_button.grid(row=0, column=1, padx=5, pady=5)

        # Butonul pentru ascunderea textului în imagine
        hide_text_button = ttk.Button(control_frame, text="Ascunde Text", command=self.hide_text_in_image)
        hide_text_button.grid(row=0, column=2, padx=5, pady=5)

        # Butonul pentru afișarea imaginii cu textul ascuns
        show_hidden_image_button = ttk.Button(control_frame, text="Afiseaza Imaginea cu Text Ascuns", command=self.show_hidden_image)
        show_hidden_image_button.grid(row=0, column=3, padx=5, pady=5)

        # Butonul pentru extragerea textului ascuns din imagine
        extract_text_button = ttk.Button(control_frame, text="Extrage Text", command=self.extract_text_from_image)
        extract_text_button.grid(row=0, column=4, padx=5, pady=5)

        # Variabile pentru a reține calea imaginii și textul
        self.image_path = None
        self.text_to_hide = None

        # Variabilă pentru a reține imaginea cu textul ascuns
        self.hidden_image = None

        # Variabilă pentru a reține textul extras din imagine
        self.extracted_text = None

        # Imaginea afișată
        self.image_label = ttk.Label(self.main_frame)
        self.image_label.grid(row=1, column=0, padx=5, pady=5)

    def load_image(self):
        # Alegerea imaginii
        self.image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        if self.image_path:
            self.show_image(self.image_path)

    def show_image(self, image_path):
        # Afișarea imaginii selectate
        image = Image.open(image_path)
        image.thumbnail((400, 400))
        photo = ImageTk.PhotoImage(image)
        self.image_label.config(image=photo)
        self.image_label.image = photo

    def load_text(self):
        # Alegerea textului
        self.text_to_hide = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])

    def hide_text_in_image(self):
        if not self.image_path or not self.text_to_hide:
            messagebox.showwarning("Warning", "Selecteaza o imagine si un text pentru a ascunde.")
            return

        # Încărcarea imaginii și a textului
        image = Image.open(self.image_path)
        text = open(self.text_to_hide, "r").read()

        # Ascunderea textului în imagine
        self.hidden_image = self.hide_text_in_image_alg(image, text)

    def hide_text_in_image_alg(self, image, text):
        # Algoritmul de ascundere a textului în imagine
        binary_text = ''.join(format(ord(char), '08b') for char in text)
        width, height = image.size
        if len(binary_text) > width * height * 3:
            raise ValueError("Textul este prea lung pentru a fi ascuns în această imagine.")
        image = image.convert('RGB')
        pixels = list(image.getdata())
        new_pixels = []
        text_index = 0
        for pixel in pixels:
            if text_index < len(binary_text):
                new_pixel = (pixel[0] & 254 | int(binary_text[text_index]), pixel[1], pixel[2])
                new_pixels.append(new_pixel)
                text_index += 1
            else:
                new_pixels.append(pixel)
        hidden_image = Image.new(image.mode, image.size)
        hidden_image.putdata(new_pixels)
        return hidden_image

    def show_hidden_image(self):
        # Afișarea imaginii cu textul ascuns
        if self.hidden_image:
            self.show_image_with_hidden_text()

    def show_image_with_hidden_text(self):
        # Afișarea imaginii cu textul ascuns evidențiat
        drawn_image = self.hidden_image.copy()
        draw = ImageDraw.Draw(drawn_image)
        font = ImageFont.load_default()
        text = self.extracted_text if self.extracted_text else "Text ascuns"
        draw.text((10, 10), text, fill=(255, 0, 0), font=font)
        drawn_image.show()

    def extract_text_from_image(self):
        # Extrage textul ascuns din imagine
        if self.hidden_image:
            self.extracted_text = self.extract_text_from_image_alg(self.hidden_image)
            messagebox.showinfo("Text Extracted", f"Textul ascuns din imagine: {self.extracted_text}")

    def extract_text_from_image_alg(self, image):
        # Algoritmul de extragere a textului din imagine
        image = image.convert('RGB')
        pixels = list(image.getdata())
        binary_text = ''
        for pixel in pixels:
            binary_text += str(pixel[0] & 1)
        extracted_text = ''
        for i in range(0, len(binary_text), 8):
            byte = binary_text[i:i+8]
            extracted_text += chr(int(byte, 2))
        return extracted_text.rstrip('\x00')

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyInterface(root)
    root.mainloop()
