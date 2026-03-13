import os
import sys
sys.path.append('python/public_key_encryption')
from module_lwe_pke import ModuleLWE

def main():
    with ModuleLWE(k=2, log2q=32, eta=2) as pke:
        pke.keygen()
        print("\nNative LWE Engine: High-Capacity Transparent Chunking Test Initiated!")
        print("=" * 65)
        
        for b in [64, 128, 256, 1024]:
            byte_len = b // 8
            msg = os.urandom(byte_len)
            
            print(f"[*] Testing {b}-bit ({byte_len} bytes) Payload...")
            
            pke.encrypt(msg, b)
            dec = pke.decrypt(b)
            
            chunk_size = 8
            chunk_count = (byte_len + chunk_size - 1) // chunk_size
            
            msg_hex = msg.hex()
            dec_hex = dec.hex()
            preview_len = 32
            msg_preview = msg_hex[:preview_len] + ("..." if len(msg_hex) > preview_len else "")
            dec_preview = dec_hex[:preview_len] + ("..." if len(dec_hex) > preview_len else "")

            print(f"    - Hardware Chunks  : {chunk_count} block(s)")
            print(f"    - Original Data    : {msg_preview}")
            print(f"    - Decrypted Data   : {dec_preview}")
            print(f"    - Validation       : {'SUCCESS (Match: True)' if msg == dec else 'FAILED'}")
            print("-" * 65)

if __name__ == "__main__":
    main()
