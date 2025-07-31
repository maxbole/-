import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import getpass

# 定义加密参数 (必须与加密脚本完全一致)
AES_KEY_SIZE = 32
NONCE_SIZE = 12
SALT_SIZE = 16
NUM_LAYERS = 10
PBKDF2_ITERATIONS = 600000

def derive_keys(master_key: bytes, salt: bytes, num_keys: int) -> list:
    """使用 PBKDF2HMAC-SHA256 从主密钥派生一系列子密钥"""
    print(f"正在使用 PBKDF2 进行密钥派生 (迭代次数: {PBKDF2_ITERATIONS})...")
    keys = []
    backend = default_backend()

    for i in range(num_keys):
        key_info = f"key_derivation_layer_{i}".encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=backend
        )
        derived_key = kdf.derive(master_key + key_info)
        keys.append(derived_key)
        
    return keys

def decrypt_layer(data: bytes, key: bytes) -> bytes:
    """对数据进行单层AES-256-GCM解密"""
    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def decrypt_file(filepath: str, master_key_str: str):
    """读取加密文件，进行10层解密，并恢复原始文件。"""
    if not filepath.endswith(".encrypted"):
        print(f"错误：文件 '{filepath}' 不是一个有效的加密文件。")
        return
    if not os.path.exists(filepath):
        print(f"错误：文件 '{filepath}' 不存在。")
        return

    try:
        with open(filepath, 'rb') as f:
            encrypted_data_with_salt = f.read()
    except Exception as e:
        print(f"读取加密文件时发生错误: {e}")
        return

    master_key = master_key_str.encode('utf-8')

    try:
        salt = encrypted_data_with_salt[:SALT_SIZE]
        ciphertext_all_layers = encrypted_data_with_salt[SALT_SIZE:]

        derived_keys = derive_keys(master_key, salt, NUM_LAYERS)
        
        current_data = ciphertext_all_layers
        for i in range(NUM_LAYERS - 1, -1, -1):
            print(f"正在进行第 {i+1}/{NUM_LAYERS} 层解密...")
            key = derived_keys[i]
            current_data = decrypt_layer(current_data, key)
        
        output_filepath = filepath.replace(".encrypted", ".decrypted")
        with open(output_filepath, 'wb') as f:
            f.write(current_data)
        
        print("\n解密成功！")
        print(f"加密文件: {filepath}")
        print(f"解密后的文件已保存至: {output_filepath}")

    except InvalidTag:
        print("\n解密失败！错误：密钥错误或文件已损坏/被篡改。")
    except Exception as e:
        print(f"\n解密过程中发生未知错误: {e}")

if __name__ == '__main__':
    target_file = input("请输入要解密的文件路径: ")
    password = getpass.getpass("请输入您的解密密钥 (输入时不可见): ")

    if not password:
        print("错误：密钥不能为空。")
    else:
        decrypt_file(target_file, password)
