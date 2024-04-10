from seal import *


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


def load_all_param():
    print('-' * 10 + '加载公私钥' + '-' * 10 + '\n')
    parms = EncryptionParameters(scheme_type.ckks)
    parms.load("params.sealparams")
    context = SEALContext(parms)
    loaded_public_key = PublicKey()
    loaded_public_key.load(context, "public_key.seal")
    loaded_secret_key = SecretKey()
    loaded_secret_key.load(context, "secret_key.sealsecretkey")

    return context, loaded_public_key, loaded_secret_key


def load_pub_param():
    print("-" * 10 + "加载公钥" + "-" * 10 + '\n')
    parms = EncryptionParameters(scheme_type.ckks)
    parms.load("params.sealparams")
    context = SEALContext(parms)
    loaded_public_key = PublicKey()
    loaded_public_key.load(context, "public_key.seal")
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


if __name__ == '__main__':
    context, public_key = load_pub_param()
    scale = 2.0 ** 40
    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()
    plain1 = [3.1415926] * slot_count
    plain2 = [2.3] * slot_count
    save_cipher(plain1, context, public_key, scale, cipher_name='cipher1.bin')
    save_cipher(plain2, context, public_key, scale, cipher_name='cipher2.bin')

    # 云端加载密文
    cipher1 = load_cipher(context, cipher_name='cipher1.bin')
    cipher2 = load_cipher(context, cipher_name='cipher2.bin')

    evaluator = Evaluator(context)
    add_result = evaluator.add(cipher1, cipher2)
    mul_result = evaluator.multiply(cipher1, cipher2)
    sub_result = evaluator.sub(cipher1, cipher2)

    # 边缘节点解密
    context, public_key, secret_key = load_all_param()
    ckks_encoder = CKKSEncoder(context)
    slot_count = ckks_encoder.slot_count()
    decryptor = Decryptor(context, secret_key)

    add_plain = decryptor.decrypt(add_result)
    add_plain = ckks_encoder.decode(add_plain)

    mul_plain = decryptor.decrypt(mul_result)
    mul_plain = ckks_encoder.decode(mul_plain)

    sub_plain = decryptor.decrypt(sub_result)
    sub_plain = ckks_encoder.decode(sub_plain)

    print("add_plain:  ")
    print(add_plain)
    print("mul_plain:  ")
    print(mul_plain)
    print("sub_plain:  ")
    print(sub_plain)
