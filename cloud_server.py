import logging

from flask import Flask, request, jsonify, send_file,send_from_directory

from five_algo.cs_ip_adrress import get_public_ip
from three_operator.save_cipher import load_cipher,calculate_hash
from three_operator.three_op import *

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['KEY_PATH'] = 'three_operator/'
# 设置日志级别
# logging.basicConfig(level=logging.DEBUG)

@app.route('/compute', methods=['POST'])
def compute():
    # 检查是否有两个文件和一个操作名
    if 'file1' not in request.files or 'file2' not in request.files or 'operation' not in request.form:
        return jsonify({"error": "Missing files or operation"}), 400

    file1 = request.files['file1']
    file2 = request.files['file2']
    operation = request.form['operation']

    # app.logger.info("path is exist:{}".format(os.path.exists(app.config['KEY_PATH']+"params.sealparams")))
    context, public_key = load_pub_param(app.config['KEY_PATH'])

    # 示例操作：合并文件
    file1.save(app.config['UPLOAD_FOLDER'] + 'cipher1.bin')
    file2.save(app.config['UPLOAD_FOLDER'] + 'cipher2.bin')

    cipher1 = load_cipher(context, app.config['UPLOAD_FOLDER'] + 'cipher1.bin')
    cipher2 = load_cipher(context, app.config['UPLOAD_FOLDER'] + 'cipher2.bin')
    # 这里你可以根据operation的不同执行不同的文件操作
    if operation == "add":
        res = he_add_without_decrypt(cipher1, cipher2, app.config['KEY_PATH'])
    elif operation == "sub":
        res  = he_sub_without_decrypt(cipher1,cipher2,app.config['KEY_PATH'])
    elif operation == "mul":
        res = he_mul_without_decrypt(cipher1,cipher2,app.config['KEY_PATH'])
    else:
        return jsonify({"error": "Unsupported operation"}), 400
    # 新增：将哈希值保存到文件
    salt = b'random salt' # 盐，可以修改，实现分析结果完整性
    res_hash =calculate_hash(res,salt)

    with open(app.config['UPLOAD_FOLDER']+"res_hash.txt", 'w') as hash_file:
        hash_file.write(res_hash)
    # 密文结果保存
    res.save(app.config['UPLOAD_FOLDER'] + 'res_cipher.bin')
    # return send_file(app.config['UPLOAD_FOLDER'] + 'res_cipher.bin')
    # 返回文件和哈希值
    return jsonify({
        'result_file_url': 'download/res_cipher.bin',
        'result_hash_url': 'download/res_hash.txt'
    })

@app.route('/download/<filename>', methods=['GET'])
def download(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/', methods=['GET'])
def home():
    return 'Server is running'



if __name__ == '__main__':
    get_public_ip()
    app.run(host='0.0.0.0', port=40000, debug=True)
