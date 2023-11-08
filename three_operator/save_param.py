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
    parms = EncryptionParameters(scheme_type.ckks)
    parms.load("params.sealparams")
    context = SEALContext(parms)
    loaded_public_key = PublicKey()
    loaded_public_key.load(context, "public_key.seal")
    loaded_secret_key = SecretKey()
    loaded_secret_key.load(context, "secret_key.sealsecretkey")

    return context, loaded_public_key, loaded_secret_key


def load_pub_param():
    parms = EncryptionParameters(scheme_type.ckks)
    parms.load("params.sealparams")
    context = SEALContext(parms)
    loaded_public_key = PublicKey()
    loaded_public_key.load(context, "public_key.seal")
    return context, loaded_public_key


if __name__ == "__main__":
    save_params()


