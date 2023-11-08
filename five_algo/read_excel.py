import pandas as pd


def read_test(excel_file):
    # 1. 读取Excel文件
    data = pd.read_excel(excel_file)

    # 2. 打印表头
    print("表头:")
    print(data.columns)  # 打印表头的列名

    # 3. 遍历每一行数据
    print("\n数据行:")
    for index, row in data.iterrows():
        print(f"行索引: {index}")
        print(row[1])  # 打印每一行的数据

def excel_to_narray(excel_file):
    # 读取Excel文件
    data = pd.read_excel(excel_file)

    # 提取特征数据（data）和标签（label）
    data_features = data.iloc[:, :-1]  # 去掉最后一列（标签）
    data_labels = data.iloc[:, -1]  # 最后一列（标签）

    # 将数据特征转换为NumPy数组并转换为float类型
    data_array = data_features.to_numpy().astype(float)

    # 将标签转换为NumPy数组并转换为float类型
    label_array = data_labels.to_numpy().astype(float)

    # 现在，data_array 包含数据特征，label_array 包含标签
    # print("数据特征 (data_array):")
    # print(data_array)
    #
    # print("标签 (label_array):")
    # print(label_array)

    return data_array,data_labels


if __name__ == '__main__':
    excel_file = "data_train.xlsx"
    excel_to_narray(excel_file)
