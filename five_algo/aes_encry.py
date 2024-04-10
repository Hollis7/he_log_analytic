from Crypto.Cipher import AES

aes_key_path = "aes_key/"


# 将密钥和 IV 保存到文件
def save_key_iv(password, iv, key_filename, iv_filename):
    with open(key_filename, 'wb') as key_file:
        key_file.write(password)
    with open(iv_filename, 'wb') as iv_file:
        iv_file.write(iv)


# 从文件加载密钥和 IV
def load_key_iv(key_filename, iv_filename):
    with open(key_filename, 'rb') as key_file:
        password = key_file.read()
    with open(iv_filename, 'rb') as iv_file:
        iv = iv_file.read()
    return password, iv


if __name__ == '__main__':
    # password = b'1234567812345678'  # 秘钥，b就是表示为bytes类型
    # iv = b'1234567812345678'  # iv偏移量，bytes类型
    # save_key_iv(password, iv, aes_key_path + 'key.bin', aes_key_path + 'iv.bin')
    # 从文件加载密钥和 IV
    password, iv = load_key_iv(aes_key_path + 'key.bin', aes_key_path + 'iv.bin')
    text = b'abcdefghijklmnhi'  # 需要加密的内容，bytes类型
    aes = AES.new(password, AES.MODE_CBC, iv)  # 创建一个aes对象
    # AES.MODE_CBC 表示模式是CBC模式
    en_text = aes.encrypt(text)
    print("密文：", en_text)  # 加密明文，bytes类型
    aes = AES.new(password, AES.MODE_CBC, iv)  # CBC模式下解密需要重新创建一个aes对象
    den_text = aes.decrypt(en_text)
    print("明文：", den_text)
