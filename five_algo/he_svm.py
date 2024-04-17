from five_algo_analysis import *
from numpy import *
from seal import *

# 服务器公私钥位置
seal_key_path = '../three_operator/'


def he_calculator(cipher_list):
    print("-" * 10 + "加载密态svm权重" + "-" * 10 + '\n')
    w = loadtxt("w.txt").tolist()
    context, public_key, secret_key = load_all_param(seal_key_path)
    scale = 2.0 ** 40
    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()

    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    decryptor = Decryptor(context, secret_key)
    w_slot = [0] * slot_count
    for i in range(len(w)):
        w_slot[i] = w[i]
    encode_w = ckks_encoder.encode(w_slot, scale)
    cipher_w = encryptor.encrypt(encode_w)
    res_list = []

    print("-" * 10 + "密态svm计算" + "-" * 10 + '\n')
    for i in range(len(cipher_list)):
        res = evaluator.multiply(cipher_w, cipher_list[i])
        res_list.append(res)
    plain_res_list = []
    plain_res = [0] * len(w)
    for i in range(len(cipher_list)):
        res = decryptor.decrypt(res_list[i])
        res = ckks_encoder.decode(res)
        for j in range(len(w)):
            plain_res[j] = res[j]
        plain_res_list.append(array(plain_res))
    return plain_res_list


def he_predict(data, label):
    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0
    b = loadtxt("b.txt")
    for i in range(len(data)):
        f = sum(data[i]) + b
        if f > 0:
            res = 1
        else:
            res = -1

        if res == 1 and label[i] == 1:
            true_positives += 1
        elif res == 1 and label[i] == -1:
            false_positives += 1
        elif res == -1 and label[i] == 1:
            false_negatives += 1
        else:
            true_negatives += 1

    # 计算准确率（Accuracy）
    accuracy = (true_positives + true_negatives) / len(data)

    # 计算召回率（Recall）
    recall = true_positives / (true_positives + false_negatives)

    # 计算 F1 分数（F1-Score）
    f1_score = 2 * (true_positives / (2 * true_positives + false_positives + false_negatives))

    print(f"准确率（Accuracy）: {accuracy:.2f}")
    print(f"召回率（Recall）: {recall:.2f}")
    print(f"F1 分数（F1-Score）: {f1_score:.2f}")


def encry_data(excel_file):
    # 读取test数据集
    data, label = excel_to_narray(excel_file)  # 从文件加载数据
    data = data.tolist()

    # 读取数据长度
    inner_len = len(data[0])
    data_len = len(data)

    # 开始模拟加密
    encrypt_list = []
    context, public_key = load_pub_param(seal_key_path)
    scale = 2.0 ** 40
    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()
    encryptor = Encryptor(context, public_key)
    plain = [0] * slot_count
    for i in range(data_len):
        # 对每一行进行加密
        for j in range(inner_len):
            plain[j] = data[i][j]

        encode_plain = ckks_encoder.encode(plain, scale)
        # 加密
        cipher = encryptor.encrypt(encode_plain)
        encrypt_list.append(cipher)
    return encrypt_list, label


def predict_one(id):
    '''
    对某一条日志进行svm校验是否异常
    '''
    context, public_key, secret_key = load_all_param(seal_key_path)
    db_config = {
        'host': 'localhost',
        'user': 'hdb',
        'password': 'hdb',
        'database': 'seal_log',
        'port': 3309,  # 你的 MySQL 端口号
    }
    cipher_path = 'cipherbin/'
    # 连接到数据库
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()
    # SQL 查询，用于获取 disk_speed_per 数据
    sql = "SELECT user_id,svm_cipher FROM logs WHERE id = %s"
    cipher_list = []
    try:
        cursor.execute(sql, (id,))
        print("根据:id={}查询密态日志".format(id))
        result = cursor.fetchone()  # 获取符合条件的查询结果
        if result:
            user_id, svm_cipher_bin = result
            with open(inquire_cipher_path + 'svm_cipher.bin', 'wb') as f1:
                f1.write(svm_cipher_bin)
            svm_cipher = load_cipher(context, inquire_cipher_path + 'svm_cipher.bin')
            cipher_list.append(svm_cipher)
            print("读取密态svm异常检测格式数据成功！！！\n")
            plain = he_calculator(cipher_list)
            b = loadtxt("b.txt")
            f = sum(plain[0]) + b
            if (f < -1):
                print("用户{}的操作存在异常！！！！".format(user_id))
            else:
                print("用户{}的操作目前正常！！！！".format(user_id))

    except Exception as e:
        print(f"发生错误：{e}")


if __name__ == '__main__':
    # 密态测试训练svm
    # excel_path = 'datasets/'
    # excel_file = "data_test.xlsx"
    # cipher_list,label = encry_data(excel_path+excel_file)
    # plain_res_list = he_calculator(cipher_list)
    # he_predict(plain_res_list,label)

    # 某条日志记录异常检测
    predict_one(2)
    predict_one(21)
