# Nazuna_Lab
Nazuna_Lab is a multi tool (that works on windows(not tested yet on windows... but it should work) and was made as a learning project) that has: 
notes(add/view), 
password generator, 
file encryptor/decryptor (single file), 
metadata tool(images and videos), 
QR code generator, 
hash and encoding tools (MD5, SHA1, SHA256, base64, Hex encode/decode), 
text steganography (PNG LSB), 
secure file shredder (tried making it delete a file and kinda making it's original data untraceable...), 
local hosting (dev server, local and lan), 
PCAP analyzer (offline), 
Network interfaces (read only) 
even more coming soon

This project is licensed under the GNU GPL v3 License, with the additional condition that it may not be sold or distributed for profit


## Installation (linux)

```bash
git clone https://github.com/RarefiedMars415/Nazuna_Lab.git
cd Nazuna_Lab
```

### I recommend to use a virtual enviorment

```bash
python3 -m venv venv && source venv/bin/activate && pip3 install -r requirements.txt
```
### Use this if you're going to use the video metadata editor

```bash
sudo apt update && sudo apt install -y ffmpeg
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
