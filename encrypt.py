import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import getpass

# 定义加密参数
AES_KEY_SIZE = 32
NONCE_SIZE = 12
SALT_SIZE = 16
NUM_LAYERS = 10
# 为 PBKDF2 定义一个高迭代次数以增加破解难度
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
        # 每次派生使用不同的输入来确保子密钥唯一
        derived_key = kdf.derive(master_key + key_info)
        keys.append(derived_key)
        
    return keys

def encrypt_layer(data: bytes, key: bytes) -> bytes:
    """对数据进行单层AES-256-GCM加密"""
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def encrypt_file(filepath: str, master_key_str: str):
    """读取文件，进行10层加密，并保存结果。"""
    if not os.path.exists(filepath):
        print(f"错误：文件 '{filepath}' 不存在。")
        return

    try:
        with open(filepath, 'rb') as f:
            plaintext = f.read()
    except Exception as e:
        print(f"读取文件时发生错误: {e}")
        return
        
    master_key = master_key_str.encode('utf-8')
    salt = os.urandom(SALT_SIZE)
    derived_keys = derive_keys(master_key, salt, NUM_LAYERS)

    current_data = plaintext
    for i in range(NUM_LAYERS):
        print(f"正在进行第 {i+1}/{NUM_LAYERS} 层加密...")
        key = derived_keys[i]
        current_data = encrypt_layer(current_data, key)
    
    output_filepath = filepath + ".encrypted"
    try:
        with open(output_filepath, 'wb') as f:
            f.write(salt)
            f.write(current_data)
        print("\n加密成功！")
        print(f"原始文件: {filepath}")
        print(f"加密文件已保存至: {output_filepath}")
    except Exception as e:
        print(f"写入加密文件时发生错误: {e}")

if __name__ == '__main__':
    target_file = input("请输入要加密的文件路径: ")
    password = getpass.getpass("请输入您的加密密钥 (输入时不可见): ")

    if not password:
        print("错误：密钥不能为空。")
    else:
        encrypt_file(target_file, password)

