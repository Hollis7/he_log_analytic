import requests

from five_algo.cs_ip_adrress import get_public_ip
from three_operator.save_cipher import *
from three_operator.three_op import *

all_key_path = "three_operator/"
# 目标主机地址
server_url = 'http://localhost:40000/'
# 于服务器提前协商的盐
salt = b'random salt'


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
            print("-" * 10 + "服务器端成功返回同态加密结果" + "-" * 10)
            result_urls = response.json()
            result_file_response = requests.get(server_url + result_urls['result_file_url'])
            result_hash_response = requests.get(server_url + result_urls['result_hash_url'])

            # 将内容写入新文件
            with open(output_filepath + 'result_file.bin', 'wb') as output_file:
                output_file.write(result_file_response.content)
            print(f"Result saved to {output_filepath}")

            context, public_key, secret_key = load_all_param(all_key_path)
            res_cipher = load_cipher(context, cipher_name=output_filepath + 'result_file.bin')

            # 计算同态结果hash值
            cipher_hash = calculate_hash(res_cipher, salt)
            print("locally downloaded cipher_hash:{}".format(cipher_hash))
            print("result_hash_response:{}".format(result_hash_response.content))
            if cipher_hash == result_hash_response.content.decode('utf-8'):
                print("结果完整性验证hash一致")
            print("-" * 10 + "解密结果如下" + "-" * 10)
            res = decrypt_cipher(res_cipher, all_key_path)

            formatted_res = ['{:.2f}'.format(num) for num in res]
            print(formatted_res)

        else:
            print("Failed to get a valid response", response.status_code)


if __name__ == '__main__':
    get_public_ip()
    # 服务器地址
    # 客户端密文保存位置，替换为实际文件路径和操作
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
    print("client执行操作为：{}".format(operation))
    output_filepath = 'client_download/'
    send_files(server_url + 'compute', filepath1, filepath2, operation, output_filepath)
