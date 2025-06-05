# Secure-file-transfer
A Python-based command-line application that securely encrypts and uploads files using AES and RSA cryptography.
##  Features

- AES file encryption using password-derived key
- RSA key pair generation
- Uploads encrypted files to [transfer.sh](https://transfer.sh)
- Automatically stores `private_key.pem` and `public_key.pem`
- Simple and secure file sharing

##  Requirements

- Python 3.8+
- `cryptography` package
- `requests` package

Install dependencies:
```bash
pip install cryptography requests
```

##  Usage

```bash
python secure_file_transfer.py <filename>
```

You will be prompted to enter a password for encryption. The script will:

1. Encrypt the file using AES (CFB mode)
2. Generate an RSA key pair (2048-bit)
3. Upload the encrypted file to `transfer.sh`
4. Display the download URL

##  Output

- `<filename>.enc`: Encrypted file
- `private_key.pem`: Your private RSA key
- `public_key.pem`: Your public RSA key

##  Security Note

- Keep `private_key.pem` safe and never share it.
- Always verify download links and avoid sharing sensitive keys over insecure channels.

##  License

This tool is provided for educational purposes only.
