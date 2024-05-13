import hashlib

from seal import *
from Crypto.Util.number import getPrime
from Crypto.Random import random
import random as py_random


def save_params():
    parms = EncryptionParameters(scheme_type.ckks)
    poly_modulus_degree = 8192
    parms.set_poly_modulus_degree(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60, 40, 40, 60]))
    scale = 2.0 ** 40

    context = SEALContext(parms)
    parms.save("params.sealparams")

    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()
    keygen = KeyGenerator(context)

    public_key = keygen.create_public_key()
    public_key.save("public_key.seal")

    secret_key = keygen.secret_key()
    secret_key.save("secret_key.sealsecretkey")


def load_all_param(path):
    print('-' * 10 + '加载公私钥' + '-' * 10 + '\n')
    parms = EncryptionParameters(scheme_type.ckks)
    parms.load(path + "params.sealparams")
    context = SEALContext(parms)
    loaded_public_key = PublicKey()
    loaded_public_key.load(context, path + "public_key.seal")
    loaded_secret_key = SecretKey()
    loaded_secret_key.load(context, path + "secret_key.sealsecretkey")

    return context, loaded_public_key, loaded_secret_key


def load_pub_param(path):
    print("-" * 10 + "加载公钥" + "-" * 10 + '\n')
    parms = EncryptionParameters(scheme_type.ckks)
    parms.load(path + "params.sealparams")
    context = SEALContext(parms)
    loaded_public_key = PublicKey()
    loaded_public_key.load(context, path + "public_key.seal")

    return context, loaded_public_key


def save_cipher(plain, context, public_key, scale, cipher_name):
    ckks_encoder = CKKSEncoder(context)
    encryptor = Encryptor(context, public_key)
    # 编码
    encode_plain = ckks_encoder.encode(plain, scale)
    # 加密
    cipher = encryptor.encrypt(encode_plain)
    # 存储密文
    cipher.save(cipher_name)


def load_cipher(context, cipher_name):
    cipher1 = Ciphertext()
    cipher1.load(context, cipher_name)
    return cipher1


def decrypt_cipher(cipher, path):
    context, public_key, secret_key = load_all_param(path)
    ckks_encoder = CKKSEncoder(context)
    decryptor = Decryptor(context, secret_key)
    plain = decryptor.decrypt(cipher)
    result = ckks_encoder.decode(plain)
    return result


def calculate_hash(cipher, salt):
    '''
    由于cipher中存在噪声，每次生成的噪声都可能不同
    因此，参数cipher确保是相同的，比如存在在文件中，或者及时算及时tcp传输
    '''
    cipher_bytes = cipher.to_string() + salt
    # 计算哈希
    hash_object = hashlib.sha256(cipher_bytes)
    cipher_hash = hash_object.hexdigest()
    return cipher_hash


def cipher_hash_test(path):
    '''
     测试密文hash
    '''
    context, public_key = load_pub_param(path)
    cipher1 = load_cipher(context, cipher_name='cipher1.bin')
    # 密文hash测试
    salt = b'random salt'
    sha = calculate_hash(cipher1, salt)
    print(sha)


def generate_p_and_g():
    """
    生成一个随机大素数和生成元
    """
    p = getPrime(128)  # 生成一个128位的大素数
    q = (p - 1) // 2  # 确保p-1能够整除2，这样才有生成元

    while True:
        g = random.randint(2, p - 1)  # 随机选择一个g
        if pow(g, q, p) != 1:  # 检查g是否为阶为q的生成元
            return p, g


def save_p_and_g(p_g_path):
    """
    保存p,g避免每次生成
    """
    p, g = generate_p_and_g()
    with open(p_g_path, 'a') as file:
        file.write(f'{p}\n')
        file.write(f'{g}\n')


def read_p_and_g(p_g_path):
    """
    读取p和g
    """
    with open(p_g_path, 'r') as file:
        lines = file.readlines()
        p = int(lines[0].strip())  # 去除换行符并转换为整数
        g = int(lines[1].strip())
    return p, g


def generate_random_auxiliary_plain(secret_seed):
    py_random.seed(secret_seed)
    # 生成一个范围在 1 到 100 之间的随机整数
    random_number = py_random.randint(1, 100)
    print(random_number)

    return random_number


def hash_trans(m, g, p):
    """
    h(m) = g^m mod p
    """
    return pow(g, m, p)


def he_hash_test(a, b):
    '''
    h(a + b) = (g^(a + b) mod p) = ((g^a mod p) * (g^b mod p) mod p) = (h(a) * h(b) mod p)
    '''
    p_g_path = "p_and_g.txt"
    # save_p_and_g(p_g_path)
    p, g = read_p_and_g(p_g_path)

    hash_a = hash_trans(a, g, p)
    hash_b = hash_trans(b, g, p)
    a_mul_b = hash_a * hash_b % p

    hash_ab = hash_trans(a + b, g, p)
    if (a_mul_b == hash_ab):
        print("----成功------")
    else:
        print("----失败------")


def generate_auxiliary_he_cipher(auxiliary_plain, path):
    """
    @path:公私钥路径
    生成辅助明文便于验证服务器究竟在做什么
    """
    context, public_key = load_pub_param(path)
    scale = 2.0 ** 40
    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()
    auxiliary_he_plain = [0] * slot_count
    for i in range(len(auxiliary_plain)):
        auxiliary_he_plain[i] = auxiliary_plain[i]

    encryptor = Encryptor(context, public_key)
    # 编码
    encode_plain = ckks_encoder.encode(auxiliary_he_plain, scale)
    # 加密
    cipher = encryptor.encrypt(encode_plain)
    print('-' * 10 + '客户端辅助明文加密成功' + '-' * 10)
    return cipher

def auxiliary_he_cipher_test(secret_seed):
    auxiliary_plain = [0] * 5
    auxiliary_num = generate_random_auxiliary_plain(secret_seed)
    for i in range(len(auxiliary_plain)):
        auxiliary_plain[i] = auxiliary_num
    return generate_auxiliary_he_cipher(auxiliary_plain, path)

if __name__ == '__main__':
    path = './'
    # context, public_key = load_pub_param(path)
    # scale = 2.0 ** 40
    # ckks_encoder = CKKSEncoder(context)
    # slot_count = ckks_encoder.slot_count()
    # plain1 = [3] * slot_count
    # plain2 = [26] * slot_count
    # save_cipher(plain1, context, public_key, scale, cipher_name='cipher1.bin')
    # save_cipher(plain2, context, public_key, scale, cipher_name='cipher2.bin')

    # # 云端加载密文
    # cipher1 = load_cipher(context, cipher_name='cipher1.bin')
    # cipher2 = load_cipher(context, cipher_name='cipher2.bin')
    #
    # evaluator = Evaluator(context)
    # add_result = evaluator.add(cipher1, cipher2)
    # mul_result = evaluator.multiply(cipher1, cipher2)
    # sub_result = evaluator.sub(cipher1, cipher2)
    #
    # 边缘节点解密
    # context, public_key, secret_key = load_all_param()
    # ckks_encoder = CKKSEncoder(context)
    # slot_count = ckks_encoder.slot_count()
    # decryptor = Decryptor(context, secret_key)
    #
    # add_plain = decryptor.decrypt(add_result)
    # add_plain = ckks_encoder.decode(add_plain)
    #
    # mul_plain = decryptor.decrypt(mul_result)
    # mul_plain = ckks_encoder.decode(mul_plain)
    #
    # sub_plain = decryptor.decrypt(sub_result)
    # sub_plain = ckks_encoder.decode(sub_plain)
    #
    # print("add_plain:  ")
    # print(add_plain)
    # print("mul_plain:  ")
    # print(mul_plain)
    # print("sub_plain:  ")
    # print(sub_plain)

    # 测试密文hash
    # cipher_hash_test(path)

    # 测试同态hash
    # he_hash_test(a=5,b=8)

    # 测试辅助数据集
    secret_seed = 56
    for i in range(0,7):
        secret_seed +=1
        cipher=auxiliary_he_cipher_test(secret_seed)
        plain = decrypt_cipher(cipher,path)
        print(plain)
