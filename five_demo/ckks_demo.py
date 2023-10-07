from seal import *
import time

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


data= [3.6]*slot_count
plain = ckks_encoder.encode(data,scale)
cipher=encryptor.encrypt(plain)

mul_cipher = evaluator.multiply(cipher,cipher)
mul_de_plain = decryptor.decrypt(mul_cipher)
mul_decode_plain = ckks_encoder.decode(mul_de_plain)
print('-'*10+"mul"+'-'*10)
print(mul_decode_plain)

square_cipher = evaluator.square(cipher)
square_de_plain = decryptor.decrypt(square_cipher)
square_decode_plain = ckks_encoder.decode(square_de_plain)
print('-'*10+"square"+'-'*10)
print(square_decode_plain)

neg_cipher = evaluator.negate(cipher)
negate_de_plain = decryptor.decrypt(neg_cipher)
negate_decode_plain = ckks_encoder.decode(negate_de_plain)
print('-'*10+"negate"+'-'*10)
print(negate_decode_plain)

data1 = [3.4]*slot_count
plain1 = ckks_encoder.encode(data1,scale)
cipher1 = encryptor.encrypt(plain1)
sub_cipher = evaluator.sub(cipher,cipher1)
sub_de_plain = decryptor.decrypt(sub_cipher)
sub_decode_plain = ckks_encoder.decode(sub_de_plain)
print('-'*10+"sub"+'-'*10)
print(sub_decode_plain)