#!/usr/bin/python
# coding=utf-8
#import pandas as pd
import nmap
import time
import datetime
import threading
import requests
import json
import queue
import os
import concurrent.futures
import random
import re
from threading import Lock
import multiprocessing
from pebble import ProcessPool
import platform
import socket
import IPy
import gevent
from gevent import pool as async_pool
socket.setdefaulttimeout(10)

requests.packages.urllib3.disable_warnings()
locking = Lock()
human_headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.76 Safari/537.36',
    'Accept-Encoding': 'gzip,deflate,sdch',
    'Connection':'close'
}


class BoundedThreadPoolExecutor(concurrent.futures.ThreadPoolExecutor):
    def __init__(self, max_workers=None):
        super().__init__(max_workers)
        self._work_queue = queue.Queue(max_workers * 8)

class Token:
    def __init__(self):
        super().__init__()
        self.value = True



class PortScan:
    def __init__(self, target_url_ports: list):
        self.target_url_ports = target_url_ports
        self.result_queue = queue.Queue()
        self.is_running = Token()

    def is_running(self):
        time.sleep(0.01)
        return self.is_running
        #启用多线程扫描
    def multithread_scan(self,n_th=60):
        random.shuffle(self.target_url_ports)
        urls = self.chunks(self.target_url_ports, 30)
        with BoundedThreadPoolExecutor(n_th) as executor:
            for scan_urls in urls:
                executor.submit(self.portscan, scan_urls)
        self.is_running.value = False


    #调用masscan
    def portscan(self,scan_urls):
        do(scan_urls)
        self.result_queue.put(scan_urls)
        

    def chunks(self, l, n):
        """Yield successive n-sized chunks from l."""
        for i in range(0, len(l), n):
            yield l[i:i + n]

    def random_str(self,len):
        str1 = ""
        for i in range(len):
            str1 += (random.choice("ABCDEFGH1234567890"))
        return str1



class ServerScan():
    def __init__(self, task_queue: queue.Queue, token):
        self.task_queue = task_queue
        self.token = token
        self.result_queue = queue.Queue()
        super().__init__()

    def start(self):        
        while self.token.value or self.task_queue.qsize() > 0:
            try:
                task_ip_port = self.task_queue.get(timeout=8)
                print("a task done")
            except Exception as e:
                if self.task_queue.empty():
                    pass


    def terminate(self):
        self.token = False




def check_url(url):
    try:
        #print("now url live check: {}".format(url))
        res = requests.get(url, headers=human_headers,timeout=3, verify=False)
        if res.status_code == 400 or str(res.status_code)[0] == '5':
            url = "https://" + url.split("//")[1]
            r = requests.get(url, headers=human_headers, timeout=3, verify=False)
            if r.status_code == 400 or str(r.status_code)[0] == '5':
                return "none"
            else:
                return url
        else:
            return url
    except Exception as e:
        # print(e)
        try:
            url = "https://" + url.split("//")[1]
            r = requests.get(url, headers=human_headers, timeout=3, verify=False)
            if r.status_code == 400 or str(r.status_code)[0] == '5':
                return "none"
            else:
                return url
        except Exception as e:
            return "none"






def save(url):
    url = check_url(url)
    if url != "none":
        with locking:
            with open(filename, 'a+') as f:
                print("now save :{}".format(url))
                f.write("{}\n".format(url))
    else:
        pass
    return 'OK'





def do(urls):
    from gevent import monkey
    monkey.patch_all(threaded=False)
    g_pool = async_pool.Pool(30)
    tasks = [g_pool.spawn(save,url) for url in urls]
    gevent.joinall(tasks)





def start(subdomains,file):
    start_time = datetime.datetime.now()
    global filename
    filename = file
    target_urls = []
    target_url_ports = []
    #small_ports = {80, 443, 8000, 8080, 8443}
    #medium_ports = {80,81,82,83,84,85,86,87,88,89,90,443,591,888,2082,2087,2095,2096,3000,3128,3443,4040,5443,5901,5902,5906,5907,5908,5909,5200,5201,6060,6082,6443,6500,6551,6558,6901,7001,7002,7003,7004,7005,7006,7007,7008,7009,7000,7010,7011,7012,7014,7022,7080,7088,7089,7077,7200,7227,7228,7400,7379,7443,7777,7788,7798,8000,8001,8002,8008,8009,8010,8011,8012,8013,8015,8016,8017,8018,8019,8022,8040,8080,8081,8086,8088,8089,8090,8091,8092,8093,8094,8096,8099,8180,8181,8083,8200,8100,8222,8202,8280,8320,8383,8400,8443,8444,8485,8500,8600,8834,8880,8881,8882,8888,9000,9001,9002,9003,9004,9005,9006,9007,9008,9009,9010,9012,9011,9043,9080,9081,9086,9090,9091,9200,9443,9418,9500,9600,9700,9800,9900,9898,9990,9998,9999,10000,10001,10002,10006,10443,10086,11211,11500,18888,19007,19020,19191,19220,19410,19788,19998,20003,20005,12345,15672,18983,27017,21118,31021,32000,50070} 
    #large_ports = {80,81,82,83,84,85,86,87,88,89,90,443,591,888,2082,2087,2095,2096,3000,3128,3443,4040,5443,5901,5902,5906,5907,5908,5909,5200,5201,6060,6082,6443,6500,6551,6558,6901,7000,7001,7002,7003,7004,7005,7006,7007,7008,7009,7010,7011,7012,7013,7014,7015,7016,7018,7019,7020,7021,7022,7023,7024,7025,7026,7070,7077,7080,7081,7082,7083,7088,7097,7100,7103,7106,7200,7201,7388,7402,7435,7443,7485,7496,7510,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8003,8005,8006,8007,8008,8009,8010,8011,8020,8021,8022,8025,8026,8031,8042,8045,8060,8070,8077,8078,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8096,8099,8100,8101,8106,8134,8139,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8334,8336,8383,8400,8402,8443,8444,8485,8500,8553,8600,8649,8651,8652,8654,8663,8686,8701,8800,8873,8880,8881,8882,8888,8889,8899,8983,8994,8999,9000,9001,9002,9003,9009,9010,9011,9012,9021,9023,9027,9037,9040,9043,9050,9071,9080,9081,9082,9086,9090,9091,9099,9100,9101,9102,9103,9110,9111,9180,9200,9201,9205,9207,9208,9209,9210,9211,9212,9213,9220,9290,9332,9415,9418,9443,9485,9500,9502,9503,9535,9553,9575,9593,9594,9595,9618,9663,9666,9876,9877,9878,9898,9900,9908,9916,9917,9918,9919,9928,9929,9939,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10051,10080,10082,10086,10180,10215,10243,10250,10443,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11211,11967,12000,12174,12265,12345,12601,13456,13722,13782,13783,14000,14238,14441,14442,15000,15001,15002,15003,15004,15660,15672,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18080,18100,18101,18800,18801,18803,18980,18983,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22222,22345,22939,23502,24444,24800,25734,25735,26214,27000,27017,27352,27353,27355,27356,27715,28080,28201,31021,32000,50070}
    #port_list = ["1-65535"]
    port_list_str = "80,81,82,83,84,85,86,87,88,89,90,443,591,888,2082,2087,2095,2096,3000,3128,3443,4040,5443,5901,5902,5906,5907,5908,5909,5200,5201,6060,6082,6443,6500,6551,6558,6901,7000,7001,7002,7003,7004,7005,7006,7007,7008,7009,7010,7011,7012,7013,7014,7015,7016,7018,7019,7020,7021,7022,7023,7024,7025,7026,7070,7077,7080,7081,7082,7083,7088,7097,7100,7103,7106,7200,7201,7388,7402,7435,7443,7485,7496,7510,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8003,8005,8006,8007,8008,8009,8010,8011,8020,8021,8022,8025,8026,8031,8042,8045,8060,8070,8077,8078,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8096,8099,8100,8101,8106,8134,8139,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8334,8336,8383,8400,8402,8443,8444,8485,8500,8553,8600,8649,8651,8652,8654,8663,8686,8701,8800,8873,8880,8881,8882,8888,8889,8899,8983,8994,8999,9000,9001,9002,9003,9009,9010,9011,9012,9021,9023,9027,9037,9040,9043,9050,9071,9080,9081,9082,9086,9090,9091,9099,9100,9101,9102,9103,9110,9111,9180,9200,9201,9205,9207,9208,9209,9210,9211,9212,9213,9220,9290,9332,9415,9418,9443,9485,9500,9502,9503,9535,9553,9575,9593,9594,9595,9618,9663,9666,9876,9877,9878,9898,9900,9908,9916,9917,9918,9919,9928,9929,9939,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10051,10080,10082,10086,10180,10215,10243,10250,10443,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11211,11967,12000,12174,12265,12345,12601,13456,13722,13782,13783,14000,14238,14441,14442,15000,15001,15002,15003,15004,15660,15672,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18080,18100,18101,18800,18801,18803,18980,18983,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22222,22345,22939,23502,24444,24800,25734,25735,26214,27000,27017,27352,27353,27355,27356,27715,28080,28201,31021,32000,50070"

    port_list = port_list_str.split(",")
    try:
        for line in subdomains:
            line = line.strip('\n')
            if "http" not in line:
                line = "http://"+line
            if line[-1:] == "/":
                line = line[:-1]
            target_urls.append(line)
        target_urls = list(set(target_urls))
        for url in target_urls:
            for port in port_list:
                if "-" in port:
                    num1 = port.split("-")[0]
                    num2 = port.split("-")[1]
                    for i in range(int(num1),int(num2)):
                        url_port = url + ":" +str(i)
                        target_url_ports.append(url_port)
                else:               
                    url_port = url + ":" +str(port)
                    target_url_ports.append(url_port)
    except Exception as e:
        print(str(e))
    portscanner = PortScan(target_url_ports)
    threading.Thread(target=portscanner.multithread_scan).start()
    scan_queue = portscanner.result_queue
    server_scan = ServerScan(scan_queue,token=portscanner.is_running)
    server_scan.start()
    spend_time = (datetime.datetime.now() - start_time).seconds
    print('端口扫描共运行了： ' + str(spend_time) + '秒')
    return "OK"