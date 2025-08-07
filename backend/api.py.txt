from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from PIL import Image
from Crypto.Cipher import AES
import base64
import os
import io
import hashlib

app = Flask(__name__)
CORS(app)


def pad(data):
    return data + (AES.block_size - len(data) % AES.block_size) * chr(AES.block_size - len(data) % AES.block_size)


def unpad(data):
    return data[:-ord(data[len(data) - 1:])]


def encrypt_message(message, password):
    key = hashlib.sha256(password.encode()).digest()
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message).encode())
    return base64.b64encode(iv + encrypted).decode()


def decrypt_message(ciphertext, password):
    raw = base64.b64decode(ciphertext)
    iv = raw[:16]
    encrypted = raw[16:]
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted).decode())
    return decrypted


def lsb_embed(image, data):
    binary_data = ''.join(format(ord(i), '08b') for i in data)
    binary_data += '1111111111111110'  # EOF marker

    pixels = image.getdata()
    new_pixels = []
    data_index = 0

    for pixel in pixels:
        r, g, b = pixel[:3]
        if data_index < len(binary_data):
            r = (r & ~1) | int(binary_data[data_index])
            data_index += 1
        if data_index < len(binary_data):
            g = (g & ~1) | int(binary_data[data_index])
            data_index += 1
        if data_index < len(binary_data):
            b = (b & ~1) | int(binary_data[data_index])
            data_index += 1
        new_pixels.append((r, g, b))

    new_image = Image.new(image.mode, image.size)
    new_image.putdata(new_pixels)
    return new_image


def lsb_extract(image):
    pixels = list(image.getdata())
    binary_data = ''

    for pixel in pixels:
        for color in pixel[:3]:
            binary_data += str(color & 1)

    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_data = ''
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data[-2:] == '\u0000\u0000':
            break
        if decoded_data[-2:] == '\ufffe':
            break
    return decoded_data[:-2]  # remove EOF marker


@app.route('/api/hide', methods=['POST'])
def hide():
    image = Image.open(request.files['image'])
    message = request.form['message']
    password = request.form['password']

    encrypted_message = encrypt_message(message, password)
    stego_image = lsb_embed(image, encrypted_message)

    output = io.BytesIO()
    stego_image.save(output, format='PNG')
    output.seek(0)

    return send_file(output, mimetype='image/png', as_attachment=True, download_name='stego_image.png')


@app.route('/api/extract', methods=['POST'])
def extract():
    image = Image.open(request.files['image'])
    password = request.form['password']

    encrypted_message = lsb_extract(image)
    try:
        decrypted_message = decrypt_message(encrypted_message, password)
        return jsonify({'message': decrypted_message})
    except:
        return jsonify({'message': 'Decryption failed. Check password or image integrity.'}), 400


if __name__ == '__main__':
    app.run(debug=True)
