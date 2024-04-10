import pymysql
try:
    #创建与数据库的连接
    #参数分别是 指定本机 数据库用户名 数据库密码 数据库名 端口号 autocommit是是否自动提交（非常不建议，万一出问题不好回滚）
    db=pymysql.connect(host='localhost',user='hdb',password='hdb',database='seal_log',port=3309,autocommit=False)
    #创建游标对象cursor
    cursor=db.cursor()
    #使用execute()方法执行sql，如果表存在则删除
    cursor.execute('drop table if EXISTS logs')
    #创建表的sql
    sql = '''
    CREATE TABLE IF NOT EXISTS logs
        (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id int,
        disk_speed_per MEDIUMBLOB,
        cpu MEDIUMBLOB,
        gpu MEDIUMBLOB,
        pass_failed MEDIUMBLOB,
        authorization MEDIUMBLOB,
        transgression_number MEDIUMBLOB,
        up_traffic MEDIUMBLOB,
        down_traffic MEDIUMBLOB,
        svm_cipher MEDIUMBLOB,
        AES_text BLOB
        )
    '''

    cursor.execute(sql)
except Exception as e:
    print('创建表失败:', e)

finally:
    #关闭数据库连接
    db.close()
