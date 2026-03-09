from module_lwe_pke import ModuleLWE

def main():
    with ModuleLWE(k=2, log2q=6, eta=2) as pke:
        pke.keygen()

        msg = bytes([0xA5])   # 8 bits
        pke.encrypt(msg, 8)

        dec = pke.decrypt(8)

        print("msg:", msg.hex())
        print("dec:", dec.hex())
        print("match:", msg == dec)

if __name__ == "__main__":
    main()