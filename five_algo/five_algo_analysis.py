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
# 保存各个关键词密文的位置
cipher_path = 'cipherbin/'
# seal密钥的位置
seal_key_path = "./"


def excel_to_narray(excel_file):
    '''
    读取训练或者测试的excel数据
    '''
    # 读取Excel文件
    df = pd.read_excel(excel_file)

    # 获取数据和标签
    data = df.drop(columns=['label']).to_numpy()  # 删除标签列以获得数据，并转换为NumPy数组
    labels = df['label'].to_numpy()  # 获取标签列，并转换为NumPy数组

    return data, labels


def excel_to_database(excel_file):
    '''
    用日志中提取的关键词同态加密放到数据库表logs中，用excel中的表数据模拟
    '''
    print('-' * 10 + '日志数据和关键数据存储数据库表logs' + '-' * 10 + '\n')
    # 加密准备
    context, public_key = load_pub_param(seal_key_path)
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
    aes_plain = (" disk_speed_per:" + str(disk_speed_per) + " cpu:" + str(cpu) + " gpu:" + str(
        gpu) + " pass_failed:" + str(pass_failed) + " authorization：" + str(
        authorization) + "transgression number:" + str(transgression_number)).encode('utf-8')
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


def save_svm_data_to_table(plain, context, public_key, scale, cipher_name):
    """
    将svm格式的数据以同态加密的形式保存
    """
    ckks_encoder = CKKSEncoder(context)
    encryptor = Encryptor(context, public_key)
    # 编码
    encode_plain = ckks_encoder.encode(plain, scale)
    # 加密
    cipher = encryptor.encrypt(encode_plain)
    # 存储密文
    cipher.save(cipher_name)


inquire_cipher_path = "inquire_cipherbin/"


def log_flow_statistics(user_id):
    """
    上传和下载流量统计
    """
    # 密态运算准备
    print('-' * 10 + '密态运算准备' + '-' * 10)
    context, public_key, secret_key = load_all_param(seal_key_path)
    # 连接到数据库
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    # SQL 查询，用于获取 disk_speed_per 数据
    print('-' * 10 + '连接数据库并查询密态结果' + '-' * 10 + '\n')
    sql = "SELECT up_traffic,down_traffic FROM logs WHERE user_id = %s"
    try:
        cursor.execute(sql, (user_id,))
        results = cursor.fetchall()  # 获取所有符合条件的查询结果
        up_traffic_cipher_list = []
        down_traffic_cipher_list = []
        if results:
            for result in results:
                up_traffic_bin, down_traffic_bin = result
                with open(inquire_cipher_path + 'up_traffic_cipher.bin', 'wb') as f1:
                    f1.write(up_traffic_bin)
                with open(inquire_cipher_path + 'down_traffic_cipher.bin', 'wb') as f2:
                    f2.write(down_traffic_bin)
                up_traffic_cipher = load_cipher(context, inquire_cipher_path + 'up_traffic_cipher.bin')
                down_traffic_cipher = load_cipher(context, inquire_cipher_path + 'down_traffic_cipher.bin')
                up_traffic_cipher_list.append(up_traffic_cipher)
                down_traffic_cipher_list.append(down_traffic_cipher)

        he_add_n(up_traffic_cipher_list, "上传流量量统计:", seal_key_path,pf=True)
        he_add_n(down_traffic_cipher_list, "下载流量统计:", seal_key_path,pf=True)

    except Exception as e:
        print(f"发生错误：{e}")


def log_transgressions_statistics(user_id):
    """
    密态越权次数统计
    """
    # 密态运算准备
    print('-' * 10 + '密态运算准备' + '-' * 10 + '\n')
    context, public_key, secret_key = load_all_param(seal_key_path)
    # 连接到数据库
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    # SQL 查询，用于获取 disk_speed_per 数据
    print('-' * 10 + '连接数据库并查询密态结果' + '-' * 10 + '\n')
    sql = "SELECT transgression_number FROM logs WHERE user_id = %s"
    try:
        cursor.execute(sql, (user_id,))
        results = cursor.fetchall()  # 获取所有符合条件的查询结果
        transgression_number_cipher_list = []
        if results:
            for result in results:
                with open(inquire_cipher_path + 'transgression_number_cipher.bin', 'wb') as f1:
                    f1.write(result[0])
                transgression_number_cipher = load_cipher(context,
                                                          inquire_cipher_path + 'transgression_number_cipher.bin')
                transgression_number_cipher_list.append(transgression_number_cipher)

        nums = he_add_n(transgression_number_cipher_list, "越权次数统计:",seal_key_path)
        print("用户：{}越权次数一共{}次".format(user_id, int(nums[0])))
    except Exception as e:
        print(f"发生错误：{e}")


def log_pass_failed_statistics(user_id):
    """
    登录失败统计
    """
    # 密态运算准备
    print('-' * 10 + '密态运算准备' + '-' * 10 + '\n')
    context, public_key, secret_key = load_all_param(seal_key_path)
    # 连接到数据库
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    # SQL 查询，用于获取 disk_speed_per 数据
    print('-' * 10 + '连接数据库并查询密态结果' + '-' * 10 + '\n')
    sql = "SELECT pass_failed FROM logs WHERE user_id = %s"
    try:
        cursor.execute(sql, (user_id,))
        results = cursor.fetchall()  # 获取所有符合条件的查询结果
        pass_failed_cipher_list = []
        if results:
            for result in results:
                with open(inquire_cipher_path + 'pass_failed_cipher.bin', 'wb') as f1:
                    f1.write(result[0])
                pass_failed_cipher = load_cipher(context, inquire_cipher_path + 'pass_failed_cipher.bin')
                pass_failed_cipher_list.append(pass_failed_cipher)

        nums = he_add_n(pass_failed_cipher_list, "登录失败统计:",seal_key_path)
        print("用户：{}登录失败一共{}次".format(user_id, int(nums[0])))
    except Exception as e:
        print(f"发生错误：{e}")
    return nums[0]


def log_load_analysis(user_id):
    """
    通过用户最新的日志，cpu、gpu、disk_speed_per(磁盘当前/最大磁盘速度）数据进行负载分析
    """
    # 密态运算准备
    print('-' * 10 + '密态运算准备' + '-' * 10 + '\n')
    context, public_key, secret_key = load_all_param(seal_key_path)
    # 连接到数据库
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    # SQL 查询，用于获取 disk_speed_per 数据
    print('-' * 10 + '连接数据库并查询密态结果' + '-' * 10 + '\n')
    sql = "SELECT cpu,gpu,disk_speed_per FROM logs WHERE user_id = %s"
    try:
        cursor.execute(sql, (user_id,))
        results = cursor.fetchall()  # 获取所有符合条件的查询结果
        cipher_list = []
        if results:
            # 去最新的数据进行分析
            result = results[len(results) - 1]
            cpu_bin, gpu_bin, disk_speed_per_bin = result
            with open(inquire_cipher_path + 'cpu_cipher.bin', 'wb') as f1:
                f1.write(cpu_bin)
            with open(inquire_cipher_path + 'gpu_cipher.bin', 'wb') as f2:
                f2.write(gpu_bin)
            with open(inquire_cipher_path + 'disk_speed_per_cipher.bin', 'wb') as f3:
                f3.write(disk_speed_per_bin)
            cpu_cipher = load_cipher(context, inquire_cipher_path + 'cpu_cipher.bin')
            gpu_cipher = load_cipher(context, inquire_cipher_path + 'gpu_cipher.bin')
            disk_speed_per_cipher = load_cipher(context, inquire_cipher_path + 'disk_speed_per_cipher.bin')

            const_ten = [10]
            const_ten_cipher = he_cihper(const_ten,seal_key_path)
            disk_speed_score = he_mul_without_decrypt(const_ten_cipher, disk_speed_per_cipher,seal_key_path)

            cipher_list.append(cpu_cipher)
            cipher_list.append(gpu_cipher)
            cpu_gpu_score = he_add_n(cipher_list, "用户最新负载分析：",seal_key_path)

            s1 = decrypt_cipher(disk_speed_score,seal_key_path)[0]
            s2 = cpu_gpu_score[0]
            finally_score = s1 + s2

            print("用户：{}最新负载分数{:.2f}".format(user_id, finally_score))
            if (finally_score >= 60): print("用户{}占用服务器资源异常！！！！".format(user_id))

    except Exception as e:
        print(f"发生错误：{e}")


if __name__ == '__main__':
    user_id = 241786
    # 数据存入数据库
    # excel_file = "datasets/table.xlsx"
    # excel_to_database(excel_file)

    # 1、流量统计
    # log_flow_statistics(user_id)

    # 2、越权次数统计
    # log_transgressions_statistics(user_id)

    # 3、登录失败统计
    # count = log_pass_failed_statistics(user_id)
    # if (int(count) >= 4): print("用户：{}账号存在风险!!!".format(user_id))

    # 4、 负载分析
    # Load_Analysis_Score = CPU + GPU + disk_speed/disk_max_speed * 10
    log_load_analysis(user_id)
