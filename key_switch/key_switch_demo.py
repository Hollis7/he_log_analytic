from seal import *

# 设置加密参数
parms = EncryptionParameters(scheme_type.ckks)
poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60, 40, 40, 60]))

# 创建加密环境
context = SEALContext(parms)

# 生成两组密钥
keygen1 = KeyGenerator(context)
public_key1 = keygen1.create_public_key()
secret_key1 = keygen1.secret_key()

keygen2 = KeyGenerator(context)
public_key2 = keygen2.create_public_key()
secret_key2 = keygen2.secret_key()

# 创建编码器、加密器、解密器
encoder = CKKSEncoder(context)
scale = 2**40

encryptor1 = Encryptor(context, public_key1)
decryptor1 = Decryptor(context, secret_key1)

encryptor2 = Encryptor(context, public_key2)
decryptor2 = Decryptor(context, secret_key2)

# 编码和加密数据
p1 = [3]*4096
p2 = [4]*4096

encode_plain1 = encoder.encode(p1, scale)
cipher1 = encryptor1.encrypt(encode_plain1)

encode_plain2 = encoder.encode(p2, scale)
cipher2 = encryptor2.encrypt(encode_plain2)

# 生成KeySwitchKeys
evaluator = Evaluator(context)
keyswitch_keys = keygen1.create_galois_keys()
keygen1.load(context)  # 创建密钥转换密钥

# 转换密文2到密钥1空间
ciphertext2_new = Ciphertext()
evaluator.keyswitch(ciphertext2, keyswitch_keys, ciphertext2_new)

# 在同一个密钥空间中执行同态加法
evaluator.add_inplace(ciphertext1, ciphertext2_new)

# 解密和输出结果
result = Plaintext()
decryptor1.decrypt(ciphertext1, result)
decoded_result = encoder.decode_double(result)

print(f"解码结果: {decoded_result}")
