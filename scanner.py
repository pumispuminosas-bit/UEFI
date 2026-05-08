import os

def analyze_blocks_in_place(filename):
    # Adresai iš binwalk, kuriuos reikia patikrinti
    offsets = [0x2ED000, 0x680000, 0x6C0000, 0x700000]
    READ_SIZE = 0x1000 # Nuskaitome po 4KB vienam blokui pradžios analizei

    with open(filename, "rb") as f:
        for offset in offsets:
            f.seek(offset)
            data = f.read(READ_SIZE)
            
            # Ieškome tavo anksčiau minėtų implantų žymų
            if b'!SCS' in data:
                print(f"[!!!] RASTAS IMPLANTAS ties {hex(offset)}")
                # Išspausdiname visą bloką ASCII formatu, kad pamatytume kontekstą
                print(data.decode('ascii', errors='ignore'))
            else:
                print(f"[ ] Blokas ties {hex(offset)} atrodo švarus (nerasta !SCS žymų).")

if __name__ == "__main__":
    analyze_blocks_in_place("backup_bios.bin")