import simplejson
import subprocess
import json
import config
from fake_useragent import UserAgent
ua = UserAgent()


def get_random_headers():
	headers = {'User-Agent': ua.random}

	return headers

'''
    使用集合去除重复的URL
    将去重后的URL存储进入queue队列
'''
def removeDuplicates(req_list):
    req_pool=set()
    try:
        for url in req_list:
            req_pool.add(url['url'].strip())
    except Exception as e :
        print(e)
        pass
    return req_pool



'''
    使用crawlergo进行目标页面URL的爬取
'''
def crawlergoGet(target):
    print("Now crawlergoGet : {}".format(target))
    try:
        cmd = [config.crawlergo_Path, "-c", config.Chrome_Path, "-t", "10","-f","smart","--fuzz-path","--custom-headers",json.dumps(get_random_headers()), "--push-to-proxy", "http://127.0.0.1:7777/", "--push-pool-max", "10","--output-mode", "json" , target]
        rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = rsp.communicate()
        #  "--[Mission Complete]--"  是任务结束的分隔字符串
        result = simplejson.loads(output.decode().split("--[Mission Complete]--")[1])
        # print(result)
        req_list = result["req_list"]
    except Exception as e:
        print(e)
        req_list=[]
        return False
    print("target {} crawlergo end~".format(target))
    print("crawlergo get url number {}".format(len(req_list)))
    return True

def main():
    return



if __name__ == '__main__':
    main()