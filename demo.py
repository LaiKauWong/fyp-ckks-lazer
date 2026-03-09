import sys
import os
sys.path.append(os.path.abspath("./src/public_key_encryption"))

from lwe_pke_wrapper import ModuleLWE

def main():
    print("========================================")
    print("Module-LWE")
    print("========================================")
    
    print("[1] Initialize...")
    lwe = ModuleLWE(k=2, log2q=6, eta=2)
    
    print("[2] Generate keys...")
    lwe.keygen()
    
    secret_msg = b"TopSecrt"
    bit_len = len(secret_msg) * 8
    print(f"[3] Original message : {secret_msg} ({bit_len} bits)")
    
    print("[4] Encrypt...")
    lwe.encrypt(secret_msg, bit_len)
    
    print("[5] Decrypt...")
    decrypted_bytes = lwe.decrypt(bit_len)
    print(f"[6] Decrypted message : {decrypted_bytes}")
    
    if secret_msg == decrypted_bytes:
        print("\nSuccess！")
    else:
        print("\nFail！")
        
    lwe.free_memory()

if __name__ == "__main__":
    main()