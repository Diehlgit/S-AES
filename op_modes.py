import base64
import time
from math import log2
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from collections import Counter as CollCounter

# Função para medir o tempo de execução
# Essa é uma função de alta ordem para medir o tempo de 
# execução de outra função qualquer
def measure_time(func):
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        print(f"Tempo de execução: {end - start:.6f} segundos\n")
        return result
    return wrapper

# Função para mostrar grau de aleatoriedade (entropia simples)
def show_randomness(ciphertext):
    data = base64.b64decode(ciphertext)
    freq = CollCounter(data)
    entropy = -sum((count/len(data)) * log2(count/len(data)) for count in freq.values())
    print(f"Entropia (aprox.): {entropy:.4f} (quanto maior, mais aleatório)\n")

# Parâmetros comuns
key = get_random_bytes(16)  # Chave AES-128
iv = get_random_bytes(16)   # Vetor de inicialização

message = input("Digite a mensagem a ser cifrada: ").encode()

print(f"Chave (base64): {base64.b64encode(key).decode()}")
print(f"IV   (base64): {base64.b64encode(iv).decode()}\n")

# 1. Modo ECB
@measure_time
def aes_ecb_encrypt(msg, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(msg, AES.block_size))
    ct_b64 = base64.b64encode(ct_bytes).decode()
    print(f"ECB ciphertext (base64): {ct_b64}")
    show_randomness(ct_b64)
    return ct_b64

# 2. Modo CBC
@measure_time
def aes_cbc_encrypt(msg, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(msg, AES.block_size))
    ct_b64 = base64.b64encode(ct_bytes).decode()
    print(f"CBC ciphertext (base64): {ct_b64}")
    show_randomness(ct_b64)
    return ct_b64

# 3. Modo CFB
@measure_time
def aes_cfb_encrypt(msg, key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ct_bytes = cipher.encrypt(msg)
    ct_b64 = base64.b64encode(ct_bytes).decode()
    print(f"CFB ciphertext (base64): {ct_b64}")
    show_randomness(ct_b64)
    return ct_b64

# 4. Modo OFB
@measure_time
def aes_ofb_encrypt(msg, key, iv):
    cipher = AES.new(key, AES.MODE_OFB, iv)
    ct_bytes = cipher.encrypt(msg)
    ct_b64 = base64.b64encode(ct_bytes).decode()
    print(f"OFB ciphertext (base64): {ct_b64}")
    show_randomness(ct_b64)
    return ct_b64

# 5. Modo CTR
@measure_time
def aes_ctr_encrypt(msg, key):
    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ct_bytes = cipher.encrypt(msg)
    ct_b64 = base64.b64encode(ct_bytes).decode()
    print(f"CTR ciphertext (base64): {ct_b64}")
    show_randomness(ct_b64)
    return ct_b64

# Executando cifragem nos modos solicitados
print("=== AES ECB ===")
aes_ecb_encrypt(message, key)

print("=== AES CBC ===")
aes_cbc_encrypt(message, key, iv)

print("=== AES CFB ===")
aes_cfb_encrypt(message, key, iv)

print("=== AES OFB ===")
aes_ofb_encrypt(message, key, iv)

print("=== AES CTR ===")
aes_ctr_encrypt(message, key)