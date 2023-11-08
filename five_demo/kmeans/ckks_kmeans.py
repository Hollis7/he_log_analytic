import time

import numpy as np
import matplotlib.pyplot as plt
import csv
from seal import *


# 计算数据点两两之间的距离
def getDistanceMatrix(datas):
    N, D = np.shape(datas)
    dists = np.zeros([N, N])

    for i in range(N):
        for j in range(N):
            vi = datas[i, :]
            vj = datas[j, :]
            dists[i, j] = np.sqrt(np.dot((vi - vj), (vi - vj)))
    return dists


def getDistanceMatrixByCKKs(datas):
    N, D = np.shape(datas)
    dists = np.zeros([N, N])

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

    vi = [0] * slot_count
    vj = [0] * slot_count

    for i in range(N):
        for j in range(N):
            vi[0:D] = datas[i]
            vj[0:D] = datas[j]
            # 编码
            encode_vi = ckks_encoder.encode(vi, scale)
            encode_vj = ckks_encoder.encode(vj, scale)
            # 加密
            cipherI = encryptor.encrypt(encode_vi)
            cipherJ = encryptor.encrypt(encode_vj)
            # 减法
            subResult = evaluator.sub(cipherI, cipherJ)
            # 平方
            squareResult = evaluator.square(subResult)
            # 解密
            squareResult = decryptor.decrypt(squareResult)
            # 解码
            decodeResult = ckks_encoder.decode(squareResult)

            DResult = decodeResult[0:D]
            sumReslut = np.sum(DResult)
            if sumReslut < 1e-9:
                sumReslut = 0
            dists[i, j] = np.sqrt(sumReslut)

    return dists


# 找到密度计算的阈值dc
# 要求平均每个点周围距离小于dc的点的数目占总点数的1%-2%
def select_dc(dists):
    '''算法1'''
    N = np.shape(dists)[0]
    tt = np.reshape(dists, N * N)
    percent = 2.0
    position = int(N * (N - 1) * percent / 100)
    dc = np.sort(tt)[position + N]

    ''' 算法 2 '''
    # N = np.shape(dists)[0]
    # max_dis = np.max(dists)
    # min_dis = np.min(dists)
    # dc = (max_dis + min_dis) / 2

    # while True:
    # n_neighs = np.where(dists<dc)[0].shape[0]-N
    # rate = n_neighs/(N*(N-1))

    # if rate>=0.01 and rate<=0.02:
    # break
    # if rate<0.01:
    # min_dis = dc
    # else:
    # max_dis = dc

    # dc = (max_dis + min_dis) / 2
    # if max_dis - min_dis < 0.0001:
    # break
    return dc


# 计算每个点的局部密度
def get_density(dists, dc, method=None):
    N = np.shape(dists)[0]
    rho = np.zeros(N)

    for i in range(N):
        if method == None:
            rho[i] = np.where(dists[i, :] < dc)[0].shape[0] - 1
        else:
            rho[i] = np.sum(np.exp(-(dists[i, :] / dc) ** 2)) - 1
    return rho


# 计算每个数据点的密度距离
# 即对每个点，找到密度比它大的所有点
# 再在这些点中找到距离其最近的点的距离
def get_deltas(dists, rho):
    N = np.shape(dists)[0]
    deltas = np.zeros(N)
    nearest_neiber = np.zeros(N)
    # 将密度从大到小排序
    index_rho = np.argsort(-rho)
    for i, index in enumerate(index_rho):
        # 对于密度最大的点
        if i == 0:
            continue

        # 对于其他的点
        # 找到密度比其大的点的序号
        index_higher_rho = index_rho[:i]
        # 获取这些点距离当前点的距离,并找最小值
        deltas[index] = np.min(dists[index, index_higher_rho])

        # 保存最近邻点的编号
        index_nn = np.argmin(dists[index, index_higher_rho])
        nearest_neiber[index] = index_higher_rho[index_nn].astype(int)

    deltas[index_rho[0]] = np.max(deltas)
    return deltas, nearest_neiber


# 通过阈值选取 rho与delta都大的点
# 作为聚类中心
def find_centers_auto(rho, deltas):
    rho_threshold = (np.min(rho) + np.max(rho)) / 2
    delta_threshold = (np.min(deltas) + np.max(deltas)) / 2
    N = np.shape(rho)[0]

    centers = []
    for i in range(N):
        if rho[i] >= rho_threshold and deltas[i] > delta_threshold:
            centers.append(i)
    return np.array(centers)


# 选取 rho与delta乘积较大的点作为
# 聚类中心
def find_centers_K(rho, deltas, K):
    rho_delta = rho * deltas
    centers = np.argsort(-rho_delta)
    return centers[:K]


def cluster_PD(rho, centers, nearest_neiber):
    K = np.shape(centers)[0]
    if K == 0:
        print("can not find centers")
        return

    N = np.shape(rho)[0]
    labs = -1 * np.ones(N).astype(int)

    # 首先对几个聚类中进行标号
    for i, center in enumerate(centers):
        labs[center] = i

    # 将密度从大到小排序
    index_rho = np.argsort(-rho)
    for i, index in enumerate(index_rho):
        # 从密度大的点进行标号
        if labs[index] == -1:
            # 如果没有被标记过
            # 那么聚类标号与距离其最近且密度比其大的点的标号相同
            labs[index] = labs[int(nearest_neiber[index])]
    return labs


def draw_decision(rho, deltas, name="0_decision.jpg"):
    plt.cla()
    for i in range(np.shape(datas)[0]):
        plt.scatter(rho[i], deltas[i], s=16., color=(0, 0, 0))
        plt.annotate(str(i), xy=(rho[i], deltas[i]), xytext=(rho[i], deltas[i]))
        plt.xlabel("rho")
        plt.ylabel("deltas")
    plt.savefig(name)
    plt.show()


def draw_cluster(datas, labs, centers, dic_colors, name="1_cluster.jpg"):
    plt.cla()
    K = np.shape(centers)[0]

    for k in range(K):
        sub_index = np.where(labs == k)
        sub_datas = datas[sub_index]
        # 画数据点
        plt.scatter(sub_datas[:, 0], sub_datas[:, 1], s=16., color=dic_colors[k])
        # 画聚类中心
        plt.scatter(datas[centers[k], 0], datas[centers[k], 1], color="k", marker="+", s=200.)
    plt.savefig(name)
    plt.show()


def basic_cluster(dc, dists):
    # 计算局部密度
    rho = get_density(dists, dc)
    # 计算密度距离
    deltas, nearest_neiber = get_deltas(dists, rho)

    # 绘制密度/距离分布图
    draw_decision(rho, deltas, name=file_name + "_decision.jpg")

    # 获取聚类中心点
    centers = find_centers_K(rho, deltas, 3)
    print("centers", centers)

    labs = cluster_PD(rho, centers, nearest_neiber)
    return centers, labs


if __name__ == "__main__":

    dic_colors = {0: (.8, 0, 0), 1: (0, .8, 0),
                  2: (0, 0, .8), 3: (.8, .8, 0),
                  4: (.8, 0, .8), 5: (0, .8, .8),
                  6: (0, 0, 0)}
    file_name = "ckks"
    datasetfile = ['iris.data']
    for filename in datasetfile:
        with open(filename, 'r') as fc:  # dataset   BreastTissue.csv iris2.csv
            reader = csv.reader(fc)
            lines1 = []
            for line in reader:
                lines1.append(line[0:-1])
        lines = lines1[0:]

        datas = np.array(lines).astype(np.float32)
        # 计算距离矩阵
        start_time = time.time()

        dists = getDistanceMatrixByCKKs(datas)

        end_time = time.time()
        execution_time = end_time - start_time
        print(f"程序执行时间：{execution_time}秒")
        # 计算dc
        dc = select_dc(dists)
        centers, labs = basic_cluster(dc, dists)
        draw_cluster(datas, labs, centers, dic_colors, name=file_name + "_cluster.jpg")