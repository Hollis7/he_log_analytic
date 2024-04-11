from seal import *
import numpy as np


def load_all_param():
    print('-' * 10 + '加载公私钥' + '-' * 10)
    parms = EncryptionParameters(scheme_type.ckks)
    parms.load("params.sealparams")
    context = SEALContext(parms)
    loaded_public_key = PublicKey()
    loaded_public_key.load(context, "public_key.seal")
    loaded_secret_key = SecretKey()
    loaded_secret_key.load(context, "secret_key.sealsecretkey")

    return context, loaded_public_key, loaded_secret_key


def load_pub_param():
    print('-' * 10 + '加载公钥' + '-' * 10)
    parms = EncryptionParameters(scheme_type.ckks)
    parms.load("params.sealparams")
    context = SEALContext(parms)
    loaded_public_key = PublicKey()
    loaded_public_key.load(context, "public_key.seal")
    return context, loaded_public_key


def he_cihper(plain):
    '''
    用户利用公钥将明文进行加密
    '''
    context, public_key = load_pub_param()
    scale = 2.0 ** 40
    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()
    he_plain = [0] * slot_count
    for i in range(len(plain)):
        he_plain[i] = plain[i]
    encryptor = Encryptor(context, public_key)
    # 编码
    encode_plain = ckks_encoder.encode(he_plain, scale)
    # 加密
    cipher = encryptor.encrypt(encode_plain)
    print('-' * 10 + '客户端明文加密成功' + '-' * 10)
    return cipher


def he_add(cipher1, cipher2):
    """
    同态加算子
    """
    print('-' * 10 + '服务器端同态加法计算' + '-' * 10)
    context, public_key, secret_key = load_all_param()
    evaluator = Evaluator(context)
    add_result = evaluator.add(cipher1, cipher2)

    print('-' * 10 + '客户端加载私钥' + '-' * 10)
    ckks_encoder = CKKSEncoder(context)
    decryptor = Decryptor(context, secret_key)

    add_plain = decryptor.decrypt(add_result)
    add_plain = ckks_encoder.decode(add_plain)

    result = np.array(add_plain)
    # 设置显示选项，禁用科学计数法
    np.set_printoptions(suppress=True)

    print('-' * 10 + 'add result' + '-' * 10)
    print(result)
    print("\n")

    return result


def he_sub(cipher1, cipher2):
    """
    同态减法算子
    """
    print('-' * 10 + '服务器端同态减法计算' + '-' * 10)
    context, public_key, secret_key = load_all_param()
    evaluator = Evaluator(context)
    sub_result = evaluator.sub(cipher1, cipher2)

    print('-' * 10 + '客户端加载私钥' + '-' * 10)
    ckks_encoder = CKKSEncoder(context)
    decryptor = Decryptor(context, secret_key)

    sub_plain = decryptor.decrypt(sub_result)
    sub_plain = ckks_encoder.decode(sub_plain)

    result = np.array(sub_plain)
    # 设置显示选项，禁用科学计数法
    np.set_printoptions(suppress=True)

    print('-' * 10 + 'sub result' + '-' * 10)
    print(result)
    print("\n")

    return result


def he_mul(cipher1, cipher2):
    """
    同态乘法算子
    """
    print('-' * 10 + '服务器端同态乘法计算' + '-' * 10 + '\n')
    context, public_key, secret_key = load_all_param()
    evaluator = Evaluator(context)
    mul_result = evaluator.multiply(cipher1, cipher2)

    print('-' * 10 + '客户端加载私钥' + '-' * 10 + '\n')
    ckks_encoder = CKKSEncoder(context)
    decryptor = Decryptor(context, secret_key)

    mul_plain = decryptor.decrypt(mul_result)
    mul_plain = ckks_encoder.decode(mul_plain)

    result = np.array(mul_plain)
    # 设置显示选项，禁用科学计数法
    np.set_printoptions(suppress=True)

    print('-' * 10 + 'mul result' + '-' * 10)
    print(result)
    print("\n")

    return result


def he_mul_without_decrypt(cipher1, cipher2):
    """
    同态乘法算子，结果不解密
    """
    print('-' * 10 + '服务器端同态乘法计算' + '-' * 10)
    context, public_key, secret_key = load_all_param()
    evaluator = Evaluator(context)
    mul_result = evaluator.multiply(cipher1, cipher2)
    return mul_result


def he_add_n(cipher_list, name, pf=False):
    '''
    多次同态加密相加
    '''
    print('-' * 10 + '服务器端同态加法多次计算' + '-' * 10)
    context, public_key, secret_key = load_all_param()
    scale = 2.0 ** 40
    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()
    encryptor = Encryptor(context, public_key)
    evaluator = Evaluator(context)
    # print('-' * 10 + '客户端加载私钥' + '-' * 10)
    decryptor = Decryptor(context, secret_key)
    base = [0] * slot_count
    base_plain = ckks_encoder.encode(base, scale)
    base_cipher = encryptor.encrypt(base_plain)
    for i in range(len(cipher_list)):
        base_cipher = evaluator.add(base_cipher, cipher_list[i])

    add_plain = decryptor.decrypt(base_cipher)
    add_plain = ckks_encoder.decode(add_plain)

    result = np.array(add_plain)
    # 设置显示选项，禁用科学计数法
    np.set_printoptions(suppress=True)
    if (pf):
        print('-' * 10 + 'n times add result' + '-' * 10)
        print(name + "{:.2f}G".format(result[0] / 1024))
        print("\n")

    return result


if __name__ == '__main__':
    p1 = [4, 5, 456, 6]
    p2 = [4, 34, 5, 5]
    c1 = he_cihper(p1)
    c2 = he_cihper(p2)
    # he add
    he_add(c1, c2)

    # he sub
    he_sub(c1, c2)

    # he mul
    he_mul(c1, c2)

    print('-' * 10 + 'end' + '-' * 10 + '\n')
