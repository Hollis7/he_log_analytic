from read_excel import *
from three_operator.save_param import *
from numpy import *
from seal import *


def he_calculator(cipher_list):
    w = loadtxt("w.txt").tolist()
    context, public_key, secret_key = load_all_param()
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
    context, public_key = load_pub_param()
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
    return encrypt_list,label


if __name__ == '__main__':
    excel_file = "data_test.xlsx"
    cipher_list,label = encry_data(excel_file)
    plain_res_list = he_calculator(cipher_list)
    he_predict(plain_res_list,label)