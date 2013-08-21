# -*- coding: UTF-8 -*- 

import requests
import cookielib
import socket
import random
import sys
sys.path.append('..')
reload(sys)
sys.setdefaultencoding('utf-8')
 
SIMSIMI_KEY = ''
 
class SimSimi:
 
    def __init__(self):
 
        self.session = requests.Session()
 
        self.chat_url = 'http://www.simsimi.com/func/req?msg=%s&lc=ch'
        self.api_url = 'http://sandbox.api.simsimi.com/request.p?key=%s&lc=ch&ft=1.0&text=%s'
 
        if not SIMSIMI_KEY:
            self.initSimSimiCookie()
 
    def initSimSimiCookie(self):
        self.session.headers.update({'Host': 'www.simsimi.com'})
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0'})
        self.session.headers.update({'Accept': 'application/json, text/javascript, */*; q=0.01'})
        self.session.headers.update({'Accept-Language': 'zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3'})
        self.session.headers.update({'Accept-Encoding': 'gzip, deflate'})
        self.session.headers.update({'DNT': '1'})
        self.session.headers.update({'Content-Type': 'application/json; charset=utf-8'})
        self.session.headers.update({'X-Requested-With': 'XMLHttpRequest'})
        self.session.headers.update({'Referer': 'http://www.simsimi.com/talk.htm'})
        # 每天每个cookie只有200次，达到上限后到wwww.simsimi.com网站上去调戏小黄鸡，抓包替换下面的cookie
        self.session.headers.update({'Cookie': 'lang=zh_CN; JSESSIONID=F915C33EF6F3C14396355E4892FB29BF; AWSELB=15E16D030EBAAAB8ACF4BD9BB7E0CA8FB501388662941563CCCE3FBA00C1966E7EFC7E79C0270B337A9EB2DC66B3E19A07708673470FDFA0B2C01AB735E6CC2ABE3DC5F3AF; sagree=true; selected_nc=ch; __utma=119922954.1173277582.1376841870.1376841870.1376841870.1; __utmb=119922954.8.9.1376841963359; __utmc=119922954; __utmz=119922954.1376841870.1.1.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=simsimi'})
        self.session.headers.update({'Connection': 'keep-alive'})
 
    def getSimSimiResult(self, message, method='normal'):
        if method == 'normal':
            r = self.session.get(self.chat_url % message)
        else:
            url = self.api_url % (SIMSIMI_KEY, message)
            r = requests.get(url)
        return r
 
    def chat(self, message=''):
        if message:
            r = self.getSimSimiResult(message, 'normal' if not SIMSIMI_KEY else 'api')
            try:
                answer = r.json()['response']
                return answer
            except:
                return random.choice([u'休息一会儿-.-!'])
        else:
            return u'叫我干嘛'
 
simsimi = SimSimi()
 
def handle(data, bot):
    return simsimi.chat(data['message'])
 
if __name__ == '__main__':
    print handle({'message': u'最后一个问题'}, None)
    print handle({'message': u'还有一个问题'}, None)
    print handle({'message': u'其实我有三个问题'}, None)

