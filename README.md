# Nazuna_Lab
Nazuna_Lab is a multi tool (that works on windows and was made as a learning project) that has:
notes(add/view)
password generator
file encryptor/decryptor (single file)
metadata tool(images and videos)
QR code generator
hash and encoding tools (MD5, SHA1, SHA256, base64, Hex encode/decode)
text steganography (PNG LSB)
secure file shredder (tried making it delete a file and kinda making it's original data untraceable...)
local hosting (dev server, local and lan)
PCAP analyzer (offline)
(even more coming soon)

## Installation (linux)

```bash
git clone https://github.com/RarefiedMars415/Nazuna_Lab.git
cd Nazuna_Lab
```

### I reccomend to use a virtual enviorment

```bash
python3 -m venv venv && source venv/bin/activate && pip3 install -r requirements.txt
```

## Start up Nazuna_Lab

```bash
python3 nazuna_lab.py
```

### To exit from the virtual enviorment
you can either close the terminal OR:
```bash
deactivate
```
