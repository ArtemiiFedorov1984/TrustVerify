import hashlib
import json
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
# Task 1: Генерация SHA-256 для файла [cite: 8]
def get_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Task 2: Создание манифеста [cite: 9]
def generate_manifest(directory):
    manifest = {}
    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)
        if os.path.isfile(path) and filename != "metadata.json":
            manifest[filename] = get_file_hash(path)
    
    with open("metadata.json", "w") as f:
        json.dump(manifest, f, indent=4)
    print("Manifest 'metadata.json' created.")

# Task 4: Генерация ключей RSA [cite: 12]
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # Сохранение закрытого ключа
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Сохранение открытого ключа
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("RSA keys generated.")

# Task 5: Подпись манифеста [cite: 13]
def sign_manifest():
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    
    with open("metadata.json", "rb") as f:
        manifest_data = f.read()
    
    signature = private_key.sign(
        manifest_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    
    with open("signature.sig", "wb") as f:
        f.write(signature)
    print("Manifest signed successfully.")

# Task 6: Верификация [cite: 14]
def verify_integrity():
    folder = "test_files"
    
    if not os.path.exists("metadata.json"):
        print("Error: metadata.json missing!")
        return False

    # Читаем старые (эталонные) хеши из манифеста
    with open("metadata.json", "r") as f:
        manifest = json.load(f)
    
    # 1. Проверка хешей (Task 3: Detecting Tampering)
    for filename, saved_hash in manifest.items():
        path = os.path.join(folder, filename)
        
        if not os.path.exists(path):
            print(f"CRITICAL: {filename} is missing!")
            return False
            
        # ВАЖНО: Считаем хеш файла ПРЯМО СЕЙЧАС
        current_hash = get_file_hash(path) 
        
        if current_hash != saved_hash:
            print(f"CRITICAL: {filename} tampered!")
            print(f"Expected: {saved_hash}")
            print(f"Actual:   {current_hash}")
            return False # Сразу выходим, если файл изменен
    
    # 2. Проверка цифровой подписи (Task 6: Authenticity)
    try:
        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        with open("metadata.json", "rb") as f:
            manifest_data = f.read()
        with open("signature.sig", "rb") as f:
            signature = f.read()

        public_key.verify(
            signature,
            manifest_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("Verification SUCCESS: Manifest is authentic and files are intact.")
        return True
    except Exception:
        print("Verification FAILED: Signature is invalid or manifest was altered.")
        return False
    

if __name__ == "__main__":
    print("--- TrustVerify CLI Tool ---")
    print("1: Generate RSA Keys (First time only)")
    print("2: Create Manifest & Sign (Sender)")
    print("3: Verify Integrity & Signature (Receiver)")
    
    choice = input("Select action (1/2/3): ")
    
  
    folder_to_watch = "test_files" 

    if choice == "1":
        generate_keys() # Создает public_key.pem и private_key.pem [cite: 12]
    elif choice == "2":
        if not os.path.exists(folder_to_watch):
            os.makedirs(folder_to_watch)
            print(f"Created folder '{folder_to_watch}'. Put some files there and run again.")
        else:
            generate_manifest(folder_to_watch) # Создает metadata.json [cite: 9]
            sign_manifest() # Создает signature.sig [cite: 13]
    elif choice == "3":
        verify_integrity() # Проверяет файлы и подпись [cite: 10, 14]
    else:
        print("Invalid choice.")
