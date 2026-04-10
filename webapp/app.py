"""
app.py — Web app Flask untuk aplikasi penyandian data
Jalankan: python3 app.py
Akses di browser: http://localhost:5000
"""

import os
import base64
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from cipher import encrypt, decrypt

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # maks 16 MB

os.makedirs('uploads', exist_ok=True)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/encrypt/text', methods=['POST'])
def encrypt_text():
    data = request.get_json()
    text = data.get('text', '')
    password = data.get('password', '')
    if not text or not password:
        return jsonify({'error': 'Teks dan password tidak boleh kosong.'}), 400
    try:
        blob = encrypt(text.encode('utf-8'), password)
        result = base64.b64encode(blob).decode()
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/decrypt/text', methods=['POST'])
def decrypt_text():
    data = request.get_json()
    cipher_b64 = data.get('text', '')
    password = data.get('password', '')
    if not cipher_b64 or not password:
        return jsonify({'error': 'Ciphertext dan password tidak boleh kosong.'}), 400
    try:
        blob = base64.b64decode(cipher_b64)
        result = decrypt(blob, password).decode('utf-8')
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': 'Dekripsi gagal. Password salah atau data tidak valid.'}), 500


@app.route('/encrypt/file', methods=['POST'])
def encrypt_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Tidak ada file yang diunggah.'}), 400
    f = request.files['file']
    password = request.form.get('password', '')
    if not password:
        return jsonify({'error': 'Password tidak boleh kosong.'}), 400

    filename = secure_filename(f.filename)
    data = f.read()
    try:
        blob = encrypt(data, password)
        out_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + '.enc')
        with open(out_path, 'wb') as out:
            out.write(blob)
        return send_file(out_path, as_attachment=True, download_name=filename + '.enc')
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/decrypt/file', methods=['POST'])
def decrypt_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Tidak ada file yang diunggah.'}), 400
    f = request.files['file']
    password = request.form.get('password', '')
    if not password:
        return jsonify({'error': 'Password tidak boleh kosong.'}), 400

    filename = secure_filename(f.filename)
    data = f.read()
    try:
        result = decrypt(data, password)
        out_name = filename[:-4] if filename.endswith('.enc') else 'decrypted_' + filename
        out_path = os.path.join(app.config['UPLOAD_FOLDER'], out_name)
        with open(out_path, 'wb') as out:
            out.write(result)
        return send_file(out_path, as_attachment=True, download_name=out_name)
    except Exception as e:
        return jsonify({'error': 'Dekripsi gagal. Password salah atau file tidak valid.'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
