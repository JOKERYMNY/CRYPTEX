# 🔐 Cryptex - أداة تشفير وحماية الملفات  
**Cryptex هي أداة مفتوحة المصدر لحماية الملفات عبر التشفير وحساب قيم الهاش، تدعم Linux و Windows وتوفر وضعين للتشغيل: CLI (سطر الأوامر) و GUI (واجهة رسومية).**  

---

## 🚀 **الميزات:**  
- 🔐 **تشفير الملفات لحمايتها**  
- 🔓 **فك التشفير بسهولة**  
- 🔍 **حساب قيم الهاش (MD5, SHA-1, SHA-256, SHA-512)**  
- 🎨 **واجهة رسومية جميلة (GUI) + دعم سطر الأوامر (CLI)**  

---

## 💻 **التثبيت والتشغيل:**  
### ✅ **لـ Linux**  
📌 **1️⃣ تحديث الحزم وتثبيت Python إن لم يكن لديك:**  
```sh
sudo apt update && sudo apt install python3 python3-pip -y


## 📌 **2️⃣تثبيت المكتبات المطلوبة:**
```sh
pip install -r requirements.txt


## 💻 **📌 3️⃣ استخدام الأداة عبر سطر الأوامر (CLI)::**
```sh
python3 cryptex.py --encrypt file.txt      # 🔐 تشفير الملف
python3 cryptex.py --decrypt file.txt.enc  # 🔓 فك التشفير
python3 cryptex.py --hash file.txt --hash-type sha256  # 🔍 حساب الهاش

## 💻 **📌 4️⃣ تشغيل الواجهة الرسومية (GUI):**

```sh
python cryptex.py --gui

## 💻 **📜 خيارات الأوامر المتاحة (CLI Options):**
```sh
python3 cryptex.py --help  # عرض قائمة الأوامر
