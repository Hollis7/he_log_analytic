import pandas as pd
from Crypto.Util.Padding import pad
from seal import *

from three_operator.save_cipher import *
from three_operator.three_op import *
import pymysql
from aes_encry import *

# 数据库连接信息
db_config = {
    'host': 'localhost',
    'user': 'hdb',
    'password': 'hdb',
    'database': 'seal_log',
    'port': 3309,  # 你的 MySQL 端口号
}
cipher_path = 'cipherbin/'

'''
读取训练或者测试的excel数据
'''
def excel_to_narray(excel_file):
    # 读取Excel文件
    df = pd.read_excel(excel_file)

    # 获取数据和标签
    data = df.drop(columns=['label']).to_numpy()  # 删除标签列以获得数据，并转换为NumPy数组
    labels = df['label'].to_numpy()  # 获取标签列，并转换为NumPy数组

    return data, labels

'''
用日志中提取的关键词同态加密放到数据库表logs中，用excel中的表数据模拟
'''
def excel_to_database(excel_file):
    print('-' * 10 + '日志数据和关键数据存储数据库表logs' + '-' * 10 + '\n')
    # 加密准备
    context, public_key = load_pub_param()
    scale = 2.0 ** 40
    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()
    # 读取Excel文件
    data = pd.read_excel(excel_file)
    # 迭代获取每一行数据
    for index, row in data.iterrows():
        # 在这里处理每一行的数据，例如打印整行数据
        # 获取每个单元格的值
        user_id = row['user_id']
        disk_speed_per = row['disk_speed_per']
        cpu = row['cpu']
        gpu = row['gpu']
        pass_failed = row['pass_failed']
        authorization = row['authorization']
        transgression_number = row['transgression_number']
        up_traffic = row['up_traffic']
        down_traffic = row['down_traffic']

        table_cipher_save(user_id, disk_speed_per, cpu, gpu, pass_failed, authorization, transgression_number,
                          up_traffic, down_traffic,
                          context, public_key, scale, slot_count, cipher_path)
    print('-' * 10 + '日志数据和关键数据存储数据库表logs完成' + '-' * 10 + '\n')

'''
对excel的每行数据进行加密，保存到数据库，取用时只取用第一个元素
'''
def table_cipher_save(user_id, disk_speed_per, cpu, gpu, pass_failed, authorization, transgression_number, up_traffic,
                      down_traffic,
                      context, public_key, scale, slot_count, cipher_path='cipherbin/'):
    disk_speed_per_plain = [disk_speed_per] * slot_count;
    save_cipher(disk_speed_per_plain, context, public_key, scale, cipher_name=cipher_path + "disk_speed_per_cipher.bin")

    cpu_plain = [cpu] * slot_count
    save_cipher(cpu_plain, context, public_key, scale, cipher_name=cipher_path + "cpu_cipher.bin")

    gpu_plain = [gpu] * slot_count
    save_cipher(gpu_plain, context, public_key, scale, cipher_name=cipher_path + "gpu_cipher.bin")

    pass_failed_plain = [pass_failed] * slot_count
    save_cipher(pass_failed_plain, context, public_key, scale, cipher_name=cipher_path + "pass_failed_cipher.bin")

    authorization_plain = [authorization] * slot_count
    save_cipher(authorization_plain, context, public_key, scale, cipher_name=cipher_path + "authorization_cipher.bin")

    transgression_number_plain = [transgression_number] * slot_count
    save_cipher(transgression_number_plain, context, public_key, scale,
                cipher_name=cipher_path + "transgression_number_cipher.bin")

    up_traffic_plain = [up_traffic] * slot_count
    save_cipher(up_traffic_plain, context, public_key, scale, cipher_name=cipher_path + "up_traffic_cipher.bin")

    down_traffic_plain = [down_traffic] * slot_count
    save_cipher(down_traffic_plain, context, public_key, scale, cipher_name=cipher_path + "down_traffic_cipher.bin")

    print('-' * 10 + 'svm格式日志数据加密' + '-' * 10 + '\n')
    svm_data_plain = [0] * slot_count
    svm_data_list = [disk_speed_per, cpu, gpu, pass_failed, authorization, transgression_number]
    for i, data in enumerate(svm_data_list):
        svm_data_plain[i] = data
    save_cipher(svm_data_plain, context, public_key, scale, cipher_name=cipher_path + "svm_cipher.bin")

    print('-' * 10 + 'AES加密日志' + '-' * 10 + '\n')
    aes_plain = (" disk_speed_per:" + str(disk_speed_per) + " cpu:" + str(cpu) + " gpu:" + str(gpu) + " pass_failed:" + str(pass_failed) + \
                " authorization：" + str(authorization) + "transgression number:" + str(transgression_number)).encode('utf-8')
    aes_key, iv = load_key_iv(aes_key_path + 'key.bin', aes_key_path + 'iv.bin')

    aes = AES.new(aes_key, AES.MODE_CBC, iv)  # 创建一个aes对象
    aes_cipher = aes.encrypt(pad(aes_plain, AES.block_size))

    # 连接到数据库
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    # 读取二进制文件
    cipher_names = ["disk_speed_per_cipher.bin", "cpu_cipher.bin", "gpu_cipher.bin", "pass_failed_cipher.bin",
                    "authorization_cipher.bin",
                    "transgression_number_cipher.bin", "up_traffic_cipher.bin", "down_traffic_cipher.bin",
                    "svm_cipher.bin"]
    cipher_list = []
    cipher_list.append(user_id)
    for name in cipher_names:
        with open(cipher_path + name, 'rb') as file:
            cipher_list.append(file.read())
    cipher_list.append(aes_cipher)
    # 插入数据到数据库
    try:
        sql = "INSERT INTO logs (user_id, disk_speed_per, cpu, gpu, pass_failed, authorization, transgression_number, up_traffic, down_traffic,svm_cipher,AES_text) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,%s,%s)"
        cursor.execute(sql, tuple(cipher_list))
        conn.commit()  # 提交事务
        print("数据已成功插入到数据库。")
    except Exception as e:
        conn.rollback()  # 如果出错，则回滚
        print(f"发生错误：{e}")
    # 关闭连接
    cursor.close()
    conn.close()


def load_cipher_from_table(save_name, user_id,context):
    # 连接到数据库
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    # SQL 查询，用于获取 disk_speed_per 数据
    sql = "SELECT disk_speed_per FROM logs WHERE user_id = %s"
    user_id = 476807  # 假设你想获取 user_id 为 1 的记录
    try:
        cursor.execute(sql, (user_id,))
        result = cursor.fetchone()  # 获取查询结果
        if result:
            disk_speed_per = result[0]
            # 假设你想将二进制数据保存到文件中
            with open(cipher_path + 'disk_speed_per_retrieved.bin', 'wb') as file:
                file.write(disk_speed_per)
            print("数据已成功读取并保存到文件中。")
        else:
            print("未找到对应的记录。")
    except Exception as e:
        print(f"发生错误：{e}")
    disk_speed_per = load_cipher(context, cipher_path + 'disk_speed_per_retrieved.bin')

    context, public_key, secret_key = load_all_param()
    ckks_encoder = CKKSEncoder(context)
    decryptor = Decryptor(context, secret_key)
    disk_speed_per_plain = decryptor.decrypt(disk_speed_per)
    disk_speed_per_plain = ckks_encoder.decode(disk_speed_per_plain)

'''
将svm格式的数据以同态加密的形式保存
'''
def save_svm_data_to_table(plain, context, public_key, scale, cipher_name):
    ckks_encoder = CKKSEncoder(context)
    encryptor = Encryptor(context, public_key)
    # 编码
    encode_plain = ckks_encoder.encode(plain, scale)
    # 加密
    cipher = encryptor.encrypt(encode_plain)
    # 存储密文
    cipher.save(cipher_name)
'''
上传和下载流量统计
'''
inquire_cipher_path = "inquire_cipherbin/"
def  log_flow_statistics(user_id):
    # 密态运算准备
    print('-' * 10 + '密态运算准备' + '-' * 10 + '\n')
    context, public_key, secret_key = load_all_param()
    # 连接到数据库
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    # SQL 查询，用于获取 disk_speed_per 数据
    sql = "SELECT up_traffic,down_traffic FROM logs WHERE user_id = %s"
    try:
        cursor.execute(sql, (user_id,))
        results = cursor.fetchall()  # 获取所有符合条件的查询结果
        up_traffic_cipher_list = []
        down_traffic_cipher_list=[]
        if results:
            for result in results:
                up_traffic_bin, down_traffic_bin = result
                with open(inquire_cipher_path + 'up_traffic_cipher.bin', 'wb') as f1:
                    f1.write(up_traffic_bin)
                with open(inquire_cipher_path + 'down_traffic_cipher.bin', 'wb') as f2:
                    f2.write(down_traffic_bin)
                up_traffic_cipher = load_cipher(context,inquire_cipher_path + 'up_traffic_cipher.bin')
                down_traffic_cipher = load_cipher(context,inquire_cipher_path + 'down_traffic_cipher.bin')
                up_traffic_cipher_list.append(up_traffic_cipher)
                down_traffic_cipher_list.append(down_traffic_cipher)

        he_add_n(up_traffic_cipher_list,"上传流量量统计:",pf=True)
        he_add_n(down_traffic_cipher_list,"下载流量统计:",pf=True)

    except Exception as e:
        print(f"发生错误：{e}")
'''
密态越权次数统计
'''
def log_transgressions_statistics(user_id):
    # 密态运算准备
    print('-' * 10 + '密态运算准备' + '-' * 10 + '\n')
    context, public_key, secret_key = load_all_param()
    # 连接到数据库
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    # SQL 查询，用于获取 disk_speed_per 数据
    sql = "SELECT transgression_number FROM logs WHERE user_id = %s"
    try:
        cursor.execute(sql, (user_id,))
        results = cursor.fetchall()  # 获取所有符合条件的查询结果
        transgression_number_cipher_list = []
        if results:
            for result in results:
                with open(inquire_cipher_path + 'transgression_number_cipher.bin', 'wb') as f1:
                    f1.write(result[0])
                transgression_number_cipher = load_cipher(context, inquire_cipher_path + 'transgression_number_cipher.bin')
                transgression_number_cipher_list.append(transgression_number_cipher)

        nums = he_add_n(transgression_number_cipher_list, "越权次数统计:",pf=False)
        print("用户：{}越权次数一共{}次".format(user_id, int(nums[0])))
    except Exception as e:
        print(f"发生错误：{e}")


if __name__ == '__main__':
    user_id = 467165
    # 数据存入数据库
    # excel_file = "datasets/table.xlsx"
    # excel_to_database(excel_file)

    # 流量统计
    # log_flow_statistics(user_id)

    # 越权次数统计
    log_transgressions_statistics(user_id)
