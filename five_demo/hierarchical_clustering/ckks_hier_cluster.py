import math
import time

import numpy as np
import sklearn
from seal import *
from sklearn.datasets import load_iris


def euler_distance(point1: np.ndarray, point2: list) -> float:
    """
    计算两点之间的欧式距离，支持多维
    """
    distance = 0.0
    D = len(point1)

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

    v1[0:D] = point1
    v2[0:D] = point2

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
    result = np.power(DResult, 2)
    dis = np.sum(result)
    dis = np.sqrt(dis)
    return dis

class ClusterNode(object):
    def __init__(self, vec, left=None, right=None, distance=-1, id=None, count=1):
        """
        :param vec: 保存两个数据聚类后形成新的中心
         :param left: 左节点
         :param right:  右节点
         :param distance: 两个节点的距离
         :param id: 用来标记哪些节点是计算过的
         :param count: 这个节点的叶子节点个数
        """
        self.vec = vec
        self.left = left
        self.right = right
        self.distance = distance
        self.id = id
        self.count = count


class Hierarchical(object):
    def __init__(self, k = 1):
        assert k > 0
        self.k = k
        self.labels = None
    def fit(self, x):
        nodes = [ClusterNode(vec=v, id=i) for i,v in enumerate(x)]
        distances = {}
        point_num, future_num = np.shape(x)  # 特征的维度
        self.labels = [ -1 ] * point_num
        currentclustid = -1
        while len(nodes) > self.k:
            min_dist = math.inf
            nodes_len = len(nodes)
            closest_part = None  # 表示最相似的两个聚类
            for i in range(nodes_len - 1):
                for j in range(i + 1, nodes_len):
                    # 为了不重复计算距离，保存在字典内
                    d_key = (nodes[i].id, nodes[j].id)
                    if d_key not in distances:
                        distances[d_key] = euler_distance(nodes[i].vec, nodes[j].vec)
                    d = distances[d_key]
                    if d < min_dist:
                        min_dist = d
                        closest_part = (i, j)
            # 合并两个聚类
            part1, part2 = closest_part
            node1, node2 = nodes[part1], nodes[part2]
            new_vec = [ (node1.vec[i] * node1.count + node2.vec[i] * node2.count ) / (node1.count + node2.count)
                        for i in range(future_num)]  ##??
            new_node = ClusterNode(vec=new_vec,
                                   left=node1,
                                   right=node2,
                                   distance=min_dist,
                                   id=currentclustid,
                                   count=node1.count + node2.count)
            currentclustid -= 1
            del nodes[part2], nodes[part1]   # 一定要先del索引较大的
            nodes.append(new_node)
        self.nodes = nodes
        self.calc_label()

    def calc_label(self):
        """
        调取聚类的结果
        """
        for i, node in enumerate(self.nodes):
            # 将节点的所有叶子节点都分类
            self.leaf_traversal(node, i)

    def leaf_traversal(self, node: ClusterNode, label):
        """
        递归遍历叶子节点
        """
        if node.left == None and node.right == None:
            self.labels[node.id] = label
        if node.left:
            self.leaf_traversal(node.left, label)
        if node.right:
            self.leaf_traversal(node.right, label)


if __name__ == '__main__':
    start_time =time.time()
    iris = load_iris()
    my = Hierarchical(4)
    my.fit(iris.data)
    print(np.array(my.labels))
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"程序执行时间：{execution_time}秒")

    # data = [[16.9,0],[38.5,0],[39.5,0],[80.8,0],[82,0],[834.6,0],[116.1,0]]
    # my = Hierarchical(4)
    # my.fit(data)
    # print(np.array(my.labels))
