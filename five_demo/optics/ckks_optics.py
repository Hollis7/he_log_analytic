import numpy as np
import matplotlib.pyplot as plt
import time
import operator
from seal import *

def compute_squared_EDM(X):
    N, D = np.shape(X)
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
            vi[0:D] = X[i]
            vj[0:D] = X[j]
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
            dists[i, j] = np.sqrt(sumReslut)

    return dists
# 显示决策图
def plotReachability(data,eps):
    plt.figure()
    plt.plot(range(0,len(data)), data)
    plt.plot([0, len(data)], [eps, eps])
    plt.show()
# 显示分类的类别
def plotFeature(data,labels):
    clusterNum = len(set(labels))
    fig = plt.figure()
    scatterColors = ['black', 'blue', 'green', 'yellow', 'red', 'purple', 'orange', 'brown']
    ax = fig.add_subplot(111)
    for i in range(-1, clusterNum):
        colorSytle = scatterColors[i % len(scatterColors)]
        subCluster = data[np.where(labels == i)]
        ax.scatter(subCluster[:, 0], subCluster[:, 1], c=colorSytle, s=12)
    plt.show()
def updateSeeds(seeds,core_PointId,neighbours,core_dists,reach_dists,disMat,isProcess):
    # 获得核心点core_PointId的核心距离
    core_dist=core_dists[core_PointId]
    # 遍历core_PointId 的每一个邻居点
    for neighbour in neighbours:
        # 如果neighbour没有被处理过，计算该核心距离
        if(isProcess[neighbour]==-1):
            # 首先计算改点的针对core_PointId的可达距离
            new_reach_dist = max(core_dist, disMat[core_PointId][neighbour])
            if(np.isnan(reach_dists[neighbour])):
                reach_dists[neighbour]=new_reach_dist
                seeds[neighbour] = new_reach_dist
            elif(new_reach_dist<reach_dists[neighbour]):
                reach_dists[neighbour] = new_reach_dist
                seeds[neighbour] = new_reach_dist
    return seeds
def OPTICS(data,eps=np.inf,minPts=15):
    # 获得距离矩阵
    orders = []
    disMat = compute_squared_EDM(data)
    # 获得数据的行和列(一共有n条数据)
    n, m = data.shape
    # np.argsort(disMat)[:,minPts-1] 按照距离进行 行排序 找第minPts个元素的索引
    # disMat[np.arange(0,n),np.argsort(disMat)[:,minPts-1]] 计算minPts个元素的索引的距离
    temp_core_distances = disMat[np.arange(0,n),np.argsort(disMat)[:,minPts-1]]
    # 计算核心距离
    core_dists = np.where(temp_core_distances <= eps, temp_core_distances, -1)
    # 将每一个点的可达距离未定义
    reach_dists= np.full((n,), np.nan)
    # 将矩阵的中小于minPts的数赋予1，大于minPts的数赋予零，然后1代表对每一行求和,然后求核心点坐标的索引
    core_points_index = np.where(np.sum(np.where(disMat <= eps, 1, 0), axis=1) >= minPts)[0]
    # 用于标识是否被处理，没有被处理，设置为-1
    isProcess = np.full((n,), -1)
    # 遍历所有的核心点
    for pointId in core_points_index:
        # 如果核心点未被分类，将其作为的种子点，开始寻找相应簇集
        if (isProcess[pointId] == -1):
            # 将点pointId标记为当前类别(即标识为已操作)
            isProcess[pointId] = 1
            orders.append(pointId)
            # 寻找种子点的eps邻域且没有被分类的点，将其放入种子集合
            neighbours = np.where((disMat[:, pointId] <= eps) & (disMat[:, pointId] > 0) & (isProcess == -1))[0]
            seeds = dict()
            seeds=updateSeeds(seeds,pointId,neighbours,core_dists,reach_dists,disMat,isProcess)
            while len(seeds)>0:
                nextId = sorted(seeds.items(), key=operator.itemgetter(1))[0][0]
                del seeds[nextId]
                isProcess[nextId] = 1
                orders.append(nextId)
                # 寻找newPoint种子点eps邻域（包含自己）
                # 这里没有加约束isProcess == -1，是因为如果加了，本是核心点的，可能就变成了非和核心点
                queryResults = np.where(disMat[:, nextId] <= eps)[0]
                if len(queryResults) >= minPts:
                    seeds=updateSeeds(seeds,nextId,queryResults,core_dists,reach_dists,disMat,isProcess)
                # 簇集生长完毕，寻找到一个类别
    # 返回数据集中的可达列表，及其可达距离
    return orders,reach_dists
def extract_dbscan(data,orders, reach_dists, eps):
    # 获得原始数据的行和列
    n,m=data.shape
    # reach_dists[orders] 将每个点的可达距离，按照有序列表排序（即输出顺序）
    # np.where(reach_dists[orders] <= eps)[0]，找到有序列表中小于eps的点的索引，即对应有序列表的索引
    reach_distIds=np.where(reach_dists[orders] <= eps)[0]
    # 正常来说：current的值的值应该比pre的值多一个索引。如果大于一个索引就说明不是一个类别
    pre=reach_distIds[0]-1
    clusterId=0
    labels=np.full((n,),-1)
    for current in reach_distIds:
        # 正常来说：current的值的值应该比pre的值多一个索引。如果大于一个索引就说明不是一个类别
        if(current-pre!=1):
            # 类别+1
            clusterId=clusterId+1
        labels[orders[current]]=clusterId
        pre=current
    return labels
data = np.loadtxt("cluster.csv", delimiter=",")
start_time = time.time()
orders,reach_dists=OPTICS(data,np.inf,30)
end_time = time.time()
execution_time = end_time - start_time
print(f"程序执行时间：{execution_time}秒")
labels=extract_dbscan(data,orders,reach_dists,3)
plt.scatter(data[:,0],data[:,1],c=labels,marker='o')
plt.title('optics(ckks) cluster')
# 保存图表为PNG文件
plt.savefig('ckks_optics.png')
plt.show()