import numpy as np
import matplotlib.pyplot as plt
from scipy.spatial.distance import pdist
from scipy.spatial.distance import squareform
import time
from seal import *

parms = EncryptionParameters(scheme_type.ckks)
poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.Create(poly_modulus_degree, [60, 40, 40, 60]))
scale = 2.0 ** 40

context = SEALContext(parms)
ckks_encoder = CKKSEncoder(context)
slot_count = ckks_encoder.slot_count()

keygen = KeyGenerator(context)
public_key = keygen.create_public_key()
secret_key = keygen.secret_key()

encryptor = Encryptor(context, public_key)
evaluator = Evaluator(context)
decryptor = Decryptor(context, secret_key)

v = [0] * slot_count
v1 = [1,2]
v2 = [1,2]
D = 2
v[0:D] = np.subtract(v1, v2)
# 编码
encode_v = ckks_encoder.encode(v, scale)
# 加密
cipher_v = encryptor.encrypt(encode_v)
# 乘法
mul_v = evaluator.multiply(cipher_v, cipher_v)
# 解密
mul_result = decryptor.decrypt(mul_v)
# 解码
decode_result = ckks_encoder.decode(mul_result)

DResult = decode_result[0:D]
sumReslut = np.sum(DResult)
if sumReslut< 1e-9:
    sumReslut =0
print(sumReslut)
v12 = np.sqrt(sumReslut)
