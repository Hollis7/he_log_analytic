import requests

from five_algo.cs_ip_adrress import get_public_ip
from three_operator.save_cipher import *
from three_operator.three_op import *

all_key_path = "three_operator/"


def send_files(url, filepath1, filepath2, operation, output_filepath):
    # 打开两个文件
    with open(filepath1, 'rb') as file1, open(filepath2, 'rb') as file2:
        files = {
            'file1': (filepath1, file1, 'application/octet-stream'),
            'file2': (filepath2, file2, 'application/octet-stream')
        }
        # 包含操作的表单数据
        data = {'operation': operation}

        # 发送POST请求
        response = requests.post(url, files=files, data=data)

        # 检查HTTP响应状态码
        if response.status_code == 200:
            # 读取响应内容（二进制数据）
            content = response.content
            # 将内容写入新文件
            with open(output_filepath + 'output_file.bin', 'wb') as output_file:
                output_file.write(content)
            print(f"Result saved to {output_filepath}")

            context, public_key, secret_key = load_all_param(all_key_path)

            res_cipher = load_cipher(context, cipher_name=output_filepath + 'output_file.bin')
            res = decrypt_cipher(res_cipher, all_key_path)

            formatted_res = ['{:.2f}'.format(num) for num in res]
            print(formatted_res)

        else:
            print("Failed to get a valid response", response.status_code)


if __name__ == '__main__':
    get_public_ip()
    # 服务器地址
    url = 'http://localhost:40000/compute'
    # 替换为实际文件路径和操作
    path = 'client_cipher/'
    filepath1 = path + 'cipher1.bin'
    filepath2 = path + 'cipher2.bin'
    # 明文数据
    p1 = [4, 5, 456, 6]
    p2 = [4, 34, 5, 5]
    # 加密
    c1 = he_cihper(p1, all_key_path)
    c2 = he_cihper(p2, all_key_path)
    c1.save(filepath1)
    c2.save(filepath2)

    operation = 'mul'  # add、mul、sub
    output_filepath = 'client_download/'
    send_files(url, filepath1, filepath2, operation, output_filepath)
