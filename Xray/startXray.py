import os
import config
def start_xray(target):
    try:
        cmd = "{} webscan --listen 127.0.0.1:7777 --html-output {}\{}.html".format(config.Xray_Path,config.Xray_report_path,target)
        os.system(cmd)
        return
    except Exception as e:
        print(str(e))
        return