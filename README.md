# PDF-analyse-suite-
# the code--

import customtkinter as ctk
from tkinter import filedialog, messagebox
import yara
import os
import re
from PyPDF2 import PdfReader
from PIL import Image, ImageTk

# --- UI Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PDFAnalyzerEngine:
    def __init__(self, yara_rule_path="pdf_redirect.yar"):
        self.rules = None
        if os.path.exists(yara_rule_path):
            try:
                self.rules = yara.compile(filepath=yara_rule_path)
            except Exception as e:
                print(f"YARA Compile Error: {e}")

    def get_metadata(self, file_path):
        metadata_info = {}
        try:
            with open(file_path, 'rb') as f:
                reader = PdfReader(f)
                info = reader.metadata
                if info:
                    for key, value in info.items():
                        clean_key = key.replace("/", "")
                        metadata_info[clean_key] = value
                return metadata_info if metadata_info else "No metadata found."
        except:
            return "Error extracting metadata."

    def count_suspicious_keywords(self, file_path):
        keywords = ["/JavaScript", "/JS", "/XFA", "/EmbeddedFile", "/OpenAction", "/AA", "/Launch", "/RichMedia"]
        counts = {k: 0 for k in keywords}
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                for k in keywords:
                    counts[k] = len(re.findall(k.encode(), content, re.IGNORECASE))
            return counts
        except:
            return None

    def get_hex_dump(self, file_path, limit=15000):
        try:
            with open(file_path, 'rb') as f:
                data = f.read(limit)
                hex_output = ""
                for i in range(0, len(data), 16):
                    chunk = data[i:i+16]
                    hex_part = " ".join(f"{b:02x}" for b in chunk)
                    ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                    hex_output += f"{i:08x}:  {hex_part:<48}  |{ascii_part}|\n"
                return hex_output
        except Exception as e:
            return f"Error: {e}"

    def scan_yara(self, file_path):
        if not self.rules: return "YARA rules not loaded."
        matches = self.rules.match(file_path)
        return [str(m) for m in matches] if matches else "Clean"

class SentinelGui(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Sentinel PDF Suite Pro v4.1 - Cipher Sync Networks")
        self.geometry("1300x850") # Slightly wider to accommodate logo space better
        self.engine = PDFAnalyzerEngine()

        # --- Load and Display Logo ---
        try:
            logo_path = os.path.join(os.path.dirname(__file__), "image_0.png")
            pil_logo = Image.open(logo_path)
            
            # Create CustomTkinter image (this handles dark/light mode automatically)
            self.ctk_logo = ctk.CTkImage(light_image=pil_logo, dark_image=pil_logo, size=(200, 70)) # Size tailored for image_0.png

            # Setup the logo label
            self.logo_label = ctk.CTkLabel(self, image=self.ctk_logo, text="")
            self.logo_label.pack(side="top", pady=(20, 10))

        except FileNotFoundError:
            # Fallback text if image not found
            self.logo_label = ctk.CTkLabel(self, text="SENTINEL PRO", font=("Roboto", 28, "bold"), text_color="#1f6aa5")
            self.logo_label.pack(side="top", pady=(20, 10))
            print("Warning: image_0.png not found. Falling back to text logo.")

        # --- Sidebar ---
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        
        # Original placeholder text logo removed, replaced with image above

        self.btn_scan = ctk.CTkButton(self.sidebar, text="📂 Analyze PDF", command=self.process_file)
        self.btn_scan.pack(pady=10, padx=20)
        
        self.status_label = ctk.CTkLabel(self.sidebar, text="Status: Ready", text_color="gray")
        self.status_label.pack(side="bottom", pady=20)

        # --- Tab System ---
        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(side="right", fill="both", expand=True, padx=15, pady=15)
        
        self.tab_summary = self.tabs.add("Triage Summary")
        self.tab_metadata = self.tabs.add("Metadata")
        self.tab_hex = self.tabs.add("Hex View")

        self.summary_text = ctk.CTkTextbox(self.tab_summary, font=("Consolas", 14))
        self.summary_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.meta_text = ctk.CTkTextbox(self.tab_metadata, font=("Consolas", 13))
        self.meta_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.hex_text = ctk.CTkTextbox(self.tab_hex, font=("Consolas", 12), fg_color="#0a0a0a", text_color="#39FF14")
        self.hex_text.pack(fill="both", expand=True, padx=10, pady=10)

    def process_file(self):
        path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if not path: return

        self.status_label.configure(text="Status: Scanning...", text_color="#ffcc00")
        for txt in [self.summary_text, self.meta_text, self.hex_text]: txt.delete("1.0", "end")

        # 1. Keyword Counter Logic
        keywords = self.engine.count_suspicious_keywords(path)
        yara_matches = self.engine.scan_yara(path)

        # 2. Build Triage Summary
        summary = f"SUMMARY REPORT: {os.path.basename(path)}\n{'='*50}\n\n"
        summary += f"[!] YARA SIGNATURES: {yara_matches}\n\n"
        summary += f"[!] SUSPICIOUS KEYWORD COUNTS:\n"
        
        for k, v in keywords.items():
            alert = " [!] HIGH RISK" if v > 0 else ""
            color_tag = "(!) " if v > 0 else "    "
            summary += f"{color_tag}{k:<15}: {v}{alert}\n"
        
        if any(v > 0 for v in keywords.values()):
            summary += f"\n[!] WARNING: This file contains active elements. Handle with caution."
        else:
            summary += f"\n[+] No common malicious keywords detected."

        self.summary_text.insert("1.0", summary)

        # 3. Metadata & Hex
        meta = self.engine.get_metadata(path)
        self.meta_text.insert("1.0", f"METADATA FOR: {path}\n{'-'*50}\n{meta}")
        self.hex_text.insert("1.0", self.engine.get_hex_dump(path))
        
        self.status_label.configure(text
      ="Status: Scan Complete", text_color="#00ff00")

if __name__ == "__main__":
    app = SentinelGui()
    app.mainloop()



