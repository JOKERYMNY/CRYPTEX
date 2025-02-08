import sys
import os
import hashlib
import argparse
from PyQt6.QtWidgets import QApplication, QWidget, QLabel, QPushButton, QMessageBox, QVBoxLayout, QFileDialog, QTextEdit, QComboBox, QLineEdit, QRadioButton

# ✅ التشفير وفك التشفير (مستقبلاً يمكن استبداله بخوارزميات أقوى)
def encrypt_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted_data = data[::-1]  # مثال بسيط، يُفضل استخدام مكتبة قوية مثل cryptography
    with open(file_path + ".enc", 'wb') as f:
        f.write(encrypted_data)
    print(f"✅ تم التشفير: {file_path}.enc")

def decrypt_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    decrypted_data = data[::-1]  # نفس الفكرة لفك التشفير
    original_name = file_path.replace(".enc", "")
    with open(original_name, 'wb') as f:
        f.write(decrypted_data)
    print(f"✅ تم فك التشفير: {original_name}")

def calculate_hash(file_path, hash_type):
    hash_func = hashlib.new(hash_type)
    with open(file_path, 'rb') as f:
        hash_func.update(f.read())
    print(f"🔍 {hash_type.upper()} Hash: {hash_func.hexdigest()}")

# ✅ تشغيل الواجهة الرسومية
class CryptexGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔐 Cryptex - أداة تشفير وحماية الملفات")
        self.setGeometry(500, 200, 600, 400)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.encrypt_button = QPushButton("🔐 تشفير الملفات")
        self.encrypt_button.clicked.connect(self.encrypt_files)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("🔓 فك التشفير")
        self.decrypt_button.clicked.connect(self.decrypt_files)
        layout.addWidget(self.decrypt_button)

        self.hash_button = QPushButton("🔍 حساب الهاش")
        self.hash_button.clicked.connect(self.calculate_hash)
        layout.addWidget(self.hash_button)

        self.setLayout(layout)

    def encrypt_files(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "📂 اختر ملف لتشفيره")
        if file_path:
            encrypt_file(file_path)
            QMessageBox.information(self, "✅ تم", f"تم تشفير الملف: {file_path}.enc")

    def decrypt_files(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "📂 اختر ملف لفك التشفير")
        if file_path:
            decrypt_file(file_path)
            QMessageBox.information(self, "✅ تم", f"تم فك التشفير: {file_path}")

    def calculate_hash(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "📂 اختر ملف لحساب الهاش")
        if file_path:
            hash_type, ok = QComboBox.getItem(self, "🔍 اختر نوع الهاش", "MD5;SHA-1;SHA-256;SHA-512".split(";"))
            if ok:
                calculate_hash(file_path, hash_type.lower())
                QMessageBox.information(self, "✅ تم", "تم حساب الهاش بنجاح!")

# ✅ دعم سطر الأوامر (CLI)
def main():
    parser = argparse.ArgumentParser(description="🔐 Cryptex - أداة تشفير وحماية الملفات")
    parser.add_argument("--encrypt", metavar="FILE", help="🔐 تشفير ملف")
    parser.add_argument("--decrypt", metavar="FILE", help="🔓 فك التشفير")
    parser.add_argument("--hash", metavar="FILE", help="🔍 حساب الهاش")
    parser.add_argument("--hash-type", metavar="TYPE", choices=["md5", "sha1", "sha256", "sha512"], help="🔹 نوع الهاش")
    parser.add_argument("--gui", action="store_true", help="🎨 تشغيل الواجهة الرسومية")
    
    args = parser.parse_args()

    if args.gui:
        app = QApplication(sys.argv)
        window = CryptexGUI()
        window.show()
        sys.exit(app.exec())

    if args.encrypt:
        encrypt_file(args.encrypt)
    elif args.decrypt:
        decrypt_file(args.decrypt)
    elif args.hash and args.hash_type:
        calculate_hash(args.hash, args.hash_type)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()