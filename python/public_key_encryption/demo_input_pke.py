from module_lwe_pke import ModuleLWE

BLOCK_BYTES = 8  # 64 bits


def chunk_bytes(data: bytes, size: int):
    return [data[i:i + size] for i in range(0, len(data), size)]


def main():
    text = input("Enter a message: ")
    msg = text.encode("utf-8")

    print("\nOriginal text :", text)
    print("UTF-8 bytes   :", msg)

    blocks = chunk_bytes(msg, BLOCK_BYTES)
    recovered = b""

    with ModuleLWE(k=2, log2q=6, eta=2) as pke:
        pke.keygen()

        print(f"\nNumber of blocks: {len(blocks)}")

        for i, block in enumerate(blocks):
            padded = block.ljust(BLOCK_BYTES, b"\x00")

            pke.encrypt(padded, 64)
            dec = pke.decrypt(64)

            recovered += dec[:len(block)]

            print(f"\nBlock {i}:")
            print("  plain bytes :", block)
            print("  decrypted   :", dec[:len(block)])

    recovered_text = recovered.decode("utf-8")

    print("\nRecovered bytes:", recovered)
    print("Recovered text :", recovered_text)
    print("Match          :", recovered == msg)


if __name__ == "__main__":
    main()