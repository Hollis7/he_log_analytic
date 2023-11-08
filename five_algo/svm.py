import sys
from numpy import *


# 定义一个函数，用于从文件加载数据集
def loadDataSet(filename):
    fr = open(filename)
    data = []  # 存储数据点
    label = []  # 存储标签
    for line in fr.readlines():
        lineAttr = line.strip().split('\t')
        data.append([float(x) for x in lineAttr[:-1]])  # 提取数据点的特征，转换为浮点数，并添加到data中
        label.append(float(lineAttr[-1]))  # 提取标签，转换为浮点数，并添加到label中
    return data, label


# 选择一个随机的索引j，确保j不等于i
def selectJrand(i, m):
    j = i
    while j == i:
        j = int(random.uniform(0, m))
    return j


# 限制alpha值在区间[L, H]内
def clipAlpha(a_j, H, L):
    if a_j > H:
        a_j = H
    if L > a_j:
        a_j = L
    return a_j


# SMO算法的核心实现
def smoSimple(data, label, C, toler, maxIter):
    dataMatrix = mat(data)
    labelMatrix = mat(label).transpose()
    b = 0.0
    iter = 0
    m, n = shape(dataMatrix)
    alpha = mat(zeros((m, 1)))  # 初始化alpha向量

    while iter < maxIter:
        alphapairChanged = 0  # 记录alpha对的改变次数
        for i in range(m):
            fxi = float(multiply(alpha, labelMatrix).T * (dataMatrix * dataMatrix[i, :].T)) + b
            Ei = fxi - float(labelMatrix[i])  # 计算预测值与真实值之间的误差
            if (labelMatrix[i] * Ei < -toler and alpha[i] < C) or (labelMatrix[i] * Ei > toler and alpha[i] > 0):
                # 如果alpha[i]不满足KKT条件，选择alpha[j]进行优化
                j = selectJrand(i, m)
                fxj = float(multiply(alpha, labelMatrix).T * (dataMatrix * dataMatrix[j, :].T)) + b
                Ej = fxj - float(labelMatrix[j])
                alphaIOld = alpha[i].copy()
                alphaJOld = alpha[j].copy()
                if labelMatrix[i] != labelMatrix[j]:
                    L = max(0, alpha[j] - alpha[i])
                    H = min(C, C + alpha[j] - alpha[i])
                else:
                    L = max(0, alpha[i] + alpha[j] - C)
                    H = min(C, alpha[j] + alpha[i])
                if L == H:
                    print("L==H")
                    continue
                eta = 2.0 * dataMatrix[i, :] * dataMatrix[j, :].T - dataMatrix[i, :] * dataMatrix[i, :].T - dataMatrix[
                                                                                                            j,
                                                                                                            :] * dataMatrix[
                                                                                                                 j, :].T
                if eta >= 0:
                    print("eta >= 0")
                    continue
                alpha[j] -= labelMatrix[j] * (Ei - Ej) / eta
                alpha[j] = clipAlpha(alpha[j], H, L)
                if abs(alpha[j] - alphaJOld) < 0.00001:
                    print("j not move enough")
                    continue
                alpha[i] += labelMatrix[j] * labelMatrix[i] * (alphaJOld - alpha[j])
                b1 = b - Ei - labelMatrix[i] * (alpha[i] - alphaIOld) * dataMatrix[i, :] * dataMatrix[i, :].T \
                     - labelMatrix[j] * (alpha[j] - alphaJOld) * dataMatrix[i, :] * dataMatrix[j, :].T
                b2 = b - Ej - labelMatrix[i] * (alpha[i] - alphaIOld) * dataMatrix[i, :] * dataMatrix[j, :].T \
                     - labelMatrix[j] * (alpha[j] - alphaJOld) * dataMatrix[j, :] * dataMatrix[j, :].T
                if alpha[i] > 0 and alpha[i] < C:
                    b = b1
                elif alpha[j] > 0 and alpha[j] < C:
                    b = b2
                else:
                    b = (b1 + b2) / 2.0
                alphapairChanged += 1
                print("iter: %d i:%d, pairs changed %d" % (iter, i, alphapairChanged))
        if alphapairChanged == 0:
            iter += 1
        else:
            iter = 0
    return b, alpha


# 主函数
def main():
    data, label = loadDataSet('testSet.txt')  # 从文件加载数据
    b, alpha = smoSimple(data, label, 0.6, 0.001, 40)  # 调用SMO算法训练SVM
    print(b)
    print(alpha)
    print("alpha length{}".format(len(alpha)))
    for i in range(100):
        if alpha[i] > 0:
            print(data[i], label[i])


def train(data, label):
    w = 0
    b, alpha = smoSimple(data, label, 0.6, 0.001, 40)  # 调用SMO算法训练SVM
    for i in range(len(data)):
        if (alpha[i] > 0):
            w += sum(alpha[i] * label[i] * data[i], axis=0)
    return w, b


def predict(w, b, data, label):
    right = 0
    for i in range(len(data)):
        f = dot(w,data[i]) + b
        if f > 0:
            res = 1
        else:
            res = -1
        if res == label[i]:
            right += 1
    print(right / len(data))


if __name__ == '__main__':
    data, label = loadDataSet('testSet.txt')  # 从文件加载数据
    w, b = train(data, label)
    data = array(data)
    predict(w,b,data,label)
