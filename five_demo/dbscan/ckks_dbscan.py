# encoding:utf-8
import time

import matplotlib.pyplot as plt
import random
import numpy as np
import math
from seal import *

list_1 = []
list_2 = []

def loadDataSet(fileName, splitChar='\t'):
    dataSet = []
    with open(fileName) as fr:
        for line in fr.readlines():
            curline = line.strip().split(splitChar)
            fltline = list(map(float, curline))
            dataSet.append(fltline)
    return dataSet


# 计算两个点之间的欧式距离，参数为两个元组
def dist(t1, t2):
    D = len(t1)

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

    v1 = [0] * slot_count
    v2 = [0] * slot_count

    v1[0:D] = t1
    v2[0:D] = t2

    # 编码
    encode_v1 = ckks_encoder.encode(v1, scale)
    encode_v2 = ckks_encoder.encode(v2, scale)
    # 加密
    cipher1 = encryptor.encrypt(encode_v1)
    cipher2 = encryptor.encrypt(encode_v2)
    # 减法
    subResult = evaluator.sub(cipher1, cipher2)
    # 解密
    decryResult = decryptor.decrypt(subResult)
    # 解码
    decodeResult = ckks_encoder.decode(decryResult)
    DResult = decodeResult[0:D]
    result = np.power(DResult,2)
    dis = np.sum(result)
    dis = np.sqrt(dis)
    return dis


# dis = dist((1,1),(3,4))
# print(dis)


# DBSCAN算法，参数为数据集，Eps为指定半径参数，MinPts为制定邻域密度阈值
def dbscan(Data, Eps, MinPts):
    num = len(Data)  # 点的个数
    # print("点的个数："+str(num))
    unvisited = [i for i in range(num)]  # 没有访问到的点的列表
    # print(unvisited)
    visited = []  # 已经访问的点的列表
    C = [-1 for i in range(num)]
    # C为输出结果，默认是一个长度为num的值全为-1的列表
    # 用k来标记不同的簇，k = -1表示噪声点
    k = -1
    # 如果还有没访问的点
    while len(unvisited) > 0:
        # 随机选择一个unvisited对象
        p = random.choice(unvisited)
        unvisited.remove(p)
        visited.append(p)
        # N为p的epsilon邻域中的对象的集合
        N = []
        for i in range(num):
            if (dist(Data[i], Data[p]) <= Eps):  # and (i!=p):
                N.append(i)
        # 如果p的epsilon邻域中的对象数大于指定阈值，说明p是一个核心对象
        if len(N) >= MinPts:
            k = k + 1
            # print(k)
            C[p] = k
            # 对于p的epsilon邻域中的每个对象pi
            for pi in N:
                if pi in unvisited:
                    unvisited.remove(pi)
                    visited.append(pi)
                    # 找到pi的邻域中的核心对象，将这些对象放入N中
                    # M是位于pi的邻域中的点的列表
                    M = []
                    for j in range(num):
                        if (dist(Data[j], Data[pi]) <= Eps):  # and (j!=pi):
                            M.append(j)
                    if len(M) >= MinPts:
                        for t in M:
                            if t not in N:
                                N.append(t)
                # 若pi不属于任何簇，C[pi] == -1说明C中第pi个值没有改动
                if C[pi] == -1:
                    C[pi] = k
        # 如果p的epsilon邻域中的对象数小于指定阈值，说明p是一个噪声点
        else:
            C[p] = -1

    return C


# 数据集二：788个点
dataSet = loadDataSet('788dataset.txt', splitChar=',')
print("---start-----")
start_time = time.time()
C = dbscan(dataSet, 2, 14)
end_time = time.time()
execution_time = end_time - start_time
print(f"程序执行时间：{execution_time}秒")
print("----end----")
print(C)
x = []
y = []
for data in dataSet:
    x.append(data[0])
    y.append(data[1])
plt.figure(figsize=(8, 6), dpi=80)
plt.scatter(x, y, c=C, marker='o')
plt.savefig("ckks_result_fig")
plt.show()
# print(x)
# print(y)
