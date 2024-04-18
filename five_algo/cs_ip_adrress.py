import requests

def get_public_ip():
    try:
        response = requests.get('https://httpbin.org/ip')
        ip = response.json()['origin']
    except Exception as e:
        ip = "Error: " + str(e)
    # 显示当前公网 IP
    print("Public IP Address:{}".format(ip))