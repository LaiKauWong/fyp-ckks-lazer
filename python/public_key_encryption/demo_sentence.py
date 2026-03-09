from module_lwe_pke import ModuleLWE

BLOCK_BYTES = 8   # 64 bits per block


def chunk_bytes(data: bytes, size: int):
    return [data[i:i + size] for i in range(0, len(data), size)]


def main():
    text = "Hello Lazer PKE!"
    msg = text.encode("utf-8")

    print("Original text :", text)
    print("Bytes         :", msg)

    blocks = chunk_bytes(msg, BLOCK_BYTES)
    recovered = b""

    with ModuleLWE(k=2, log2q=6, eta=2) as pke:
        pke.keygen()

        for i, block in enumerate(blocks):
            padded = block.ljust(BLOCK_BYTES, b"\x00")

            pke.encrypt(padded, 64)
            dec = pke.decrypt(64)

            recovered += dec[:len(block)]

            print(f"Block {i}:")
            print("  plain :", block)
            print("  dec   :", dec[:len(block)])

    text_dec = recovered.decode("utf-8")

    print("\nRecovered bytes:", recovered)
    print("Recovered text :", text_dec)
    print("Match          :", recovered == msg)


if __name__ == "__main__":
    main()