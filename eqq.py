# -*- coding: UTF-8 -*-  
#by EvilBinary 小E rootntsd@gmail.com
import sys,os
import urllib2,urllib,re,cookielib,random,os
import PyV8,encryption,json
from encryption import QQmd5
import collections
import thread
import threading
import time,md5
import logging
import logging.config


class EqqClient(threading.Thread):
    def __init__(self):
        try:
            self.uin=''
            self.pwd=''
            self.vfwebqq=''
            self.msg_id=100000
            self.clientid='82749388'
            self.psessionid=''
            self.status=''
            self.index=''
            self.port=''
            self.ptwebqq=''
            self.verifysession=''
            self.cookies=cookielib.CookieJar()
            self.cookie=collections.OrderedDict()
            opener=urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cookies))
            agents = ["Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)","Internet Explorer 7 (Windows Vista); Mozilla/4.0 ","Google Chrome 0.2.149.29 (Windows XP)","Opera 9.25 (Windows Vista)","Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1)","Opera/8.00 (Windows NT 5.1; U; en)"]
            agent = random.choice(agents)   
            opener.addheaders=[('User-agent',agent)]
            urllib2.install_opener(opener)
            threading.Thread.__init__(self)
            self.mssage_action={
                0:   lambda message: self.process_result(message),
                102: lambda message: self.process_errmsg(message),
                116: lambda message: self.process_update_vfwebqq(message)
            }
            self.poll_type_action={
                'group_message':lambda message: self.process_group_message(message),
                'shake_message':lambda message: self.process_shake_message(message),
                'message':      lambda message: self.process_buddy_message(message),
                'input_notify': lambda message: self.process_input_notify(message)
            }
            self.init_config()
            #print 'init config'
        except Exception,e:
            self.logger.exception("Exception:%s",e)
            return False
        
    def init_config(self):
        logging.basicConfig(level=logging.DEBUG,
                format='[%(asctime)s] %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S',
                filename='eqq_'+self.uin+'.log',
                filemode='w+b')
        self.logger=logging.getLogger('')
    def set_output(self):
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        formatter = logging.Formatter('[%(asctime)s] %(levelname)4s %(message)s')
        console.setFormatter(formatter)
        self.logger.addHandler(console)
    
    def set_message_action(self,code,action):
        self.mssage_action[code]=(lambda message: action(message))
    def set_poll_type_action(self,type,action):
        #print 'poll_type_action:',self.mssage_action
        self.poll_type_action[type]=(lambda message: action(message))
        #print 'poll_type_action2:',self.mssage_action
        
    def set_account(self,uin,pwd):
        self.uin=uin
        self.pwd=pwd
        pass
    def login(self):
        try:
            hostUrl='ui.ptlogin2.qq.com'
            loginUrl='https://ui.ptlogin2.qq.com/cgi-bin/login?daid=164&target=self&style=5&mibao_css=m_webqq&appid=1003903&enable_qlogin=0&no_verifyimg=1&s_url=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html&f_url=loginerroralert&strong_login=1&login_state=10&t=20130723001'
            self.logger.info(loginUrl)
            req=urllib2.Request(loginUrl)
            req.add_header('Host',hostUrl)
            u=urllib2.urlopen(req)
            content=u.read();
            loginSig=self.get_login_sig(content)
            
            self.logger.info(u.info())
            #print content
            #print "login sig:",loginSig
            cs = ['%s=%s' % (c.name, c.value) for c in self.cookies]
            self.logger.info("1++++++++++++++++++%s\n",cs)
            
            
            checkUrl='https://ssl.ptlogin2.qq.com/check?uin='+self.uin+'&appid=1003903&js_ver=10039&js_type=0&login_sig='+loginSig+'&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html&r=0.8520018253475428'
            self.logger.info(checkUrl)
            req=urllib2.Request(checkUrl)
            req.add_header('Referer', loginUrl)
            req.add_header('Host',hostUrl)
            req.add_header('Cookie','chkuin='+self.uin)
            u=urllib2.urlopen(req)
            content=u.read()
            self.logger.info(u.info())
            self.logger.info(content)
            cs = ['%s=%s' % (c.name, c.value) for c in self.cookies]
            self.logger.info("2++++++++++++++++++%s\n",cs)
            for cookie in self.cookies:
                #print cookie.name, ":",  cookie.value
                if cookie.name == 'verifysession':
                    self.verifysession=cookie.value
            
            result=self.get_match_all(content,'ptui_checkVC\\(\'(.*?)\',\'(.*?)\',\'(.*?)\'\\);')
            
            check=result.group(1)
            verifycode=result.group(2)
            verifyhex=result.group(3)
            #print verifyhex
     
            #print "check:",check,"verifycode1:",verifycode,"verifycode2:",verifyhex
            
            imageUrl='https://ssl.captcha.qq.com/getimage?aid=1003903&r=0.7745637400075793&uin='+self.uin
            self.logger.info(imageUrl)
            req=urllib2.Request(imageUrl)
            req.add_header('Referer', loginUrl)
            req.add_header('Host',hostUrl)
            self.logger.info("reqinfo3",req.headers)
            u=urllib2.urlopen(req)
            content=u.read()
            f = open(os.getcwd()+ '/verify.png', "w+b")
            f.write(content)
            f.close()   
            self.logger.info(u.info())
            cs = ['%s=%s' % (c.name, c.value) for c in self.cookies]
            self.logger.info("3++++++++++++++++++%s\n",cs)
            
            #jsUrl='https://ui.ptlogin2.qq.com/js/10039/comm.js'
            #req=urllib2.Request(jsUrl)
            #req.add_header('Referer', loginUrl)
            #req.add_header('Host',hostUrl)
            #u=urllib2.urlopen(req)
            #content=u.read()
            #f = open(os.getcwd()+ '/comm.js', "w+b")
            #f.write(content)
            #f.close()   
            #print u.info()
            #print cookie
            
            inputverifycode=raw_input("input verify:")
           
            #pwd=encode_pwd(str(pwd),str(verifycode),verifycode1)
            verifycodehex=verifyhex.upper()
            #=verifycode
            #code=uin
            #code=verifycodehex
            #code=verifycode
            #p=encode_pwd(pwd,inputverifycode.upper(),verifycodehex.upper())
            #print "pwd1:",p
            p=str(QQmd5().md5_2(self.pwd,inputverifycode,verifyhex))
            #print "pwd2:",p
            #pwd=encode_pwd(pwd,uin,verifycodehex)
            loginUrl='https://ssl.ptlogin2.qq.com/login?u='+self.uin+'&p='+str(p)+'&verifycode='+inputverifycode.upper()+'&webqq_type=10&remember_uin=1&login2qq=1&aid=1003903&u1=http%3A%2F%2Fweb2.qq.com%2Floginproxy.html%3Flogin2qq%3D1%26webqq_type%3D10&h=1&ptredirect=0&ptlang=2052&daid=164&from_ui=1&pttype=1&dumy=&fp=loginerroralert&action=3-31-18382&mibao_css=m_webqq&t=1&g=1&js_type=0&js_ver=10039&login_sig='+loginSig
            self.logger.info(loginUrl)
            req=urllib2.Request(loginUrl)
            req.add_header('Referer', loginUrl)
            req.add_header('Host','ssl.ptlogin2.qq.com')
            self.logger.info("reqinfo4",req.headers)
            u=urllib2.urlopen(req)
            content=u.read()
            self.logger.info(u.info())
            self.logger.info(content)
            self.logger.info("realurl:%s",u.geturl() )
            self.logger.info("cookie:%s",req.get_header('Cookie'))
            cs = ['%s=%s' % (c.name, c.value) for c in self.cookies]
            self.logger.info("4++++++++++++++++++%s\n",cs)
            
            result=urllib.unquote(content)
            #print "re====",result
            result=self.get_match_all(result,'ptuiCB\\(\'(.*?)\',\'(.*?)\',\'(.*?)\',\'(.*?)\',\'(.*?)\', \'(.*?)\'\\);')
            
            url=result.group(3)
            self.logger.info(url)
            req=urllib2.Request(url)
            #req.add_header('Referer', loginUrl)
            #req.add_header('Host','ptlogin4.web2.qq.com')
            u=urllib2.urlopen(req)
            content=u.read()
            self.logger.info(u.info())
            self.logger.info(self.cookies)
            self.logger.info(content)
            cs = ['%s=%s' % (c.name, c.value) for c in self.cookies]
            self.logger.info("5++++++++++++++++++%s\n",cs)
        
    
            clientid='82749388'
            #ptwebqq=''
            for cookie in self.cookies:
                #print cookie.name, ":",  cookie.value
                if cookie.name == 'ptwebqq':
                    self.ptwebqq = cookie.value
            #print "ptwebqq:",ptwebqq
            url='http://d.web2.qq.com/channel/login2'
            postData=collections.OrderedDict()
            postData['r']='{"status":"online","ptwebqq":"%s","passwd_sig":"","clientid":"%s","psessionid":null}'%(self.ptwebqq,self.clientid)
            postData['clientid']=clientid
            postData['psessionid']='null'
            #self.logger.info(url)lib.urlencode(postData)
            #print postData
            postData=urllib.urlencode(postData)
            #print "postdata:",postData
            self.logger.info(url)
            req = urllib2.Request(url,postData)
            #req.add_header('Cookie', cookies)
            req.add_header('Referer', 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=2')
            req.add_header('ContentType', 'application/x-www-form-urlencoded')
            req.add_header('Host','d.web2.qq.com')
            req.add_header('Accept','*/*')
            req.add_header('Origin','http://d.web2.qq.com')
            req.add_header('Accept-Encoding','gzip,deflate,sdch')
            req.add_header('Accept-Language','en-US,en;q=0.8,zh-CN;q=0.6,zh;q=0.4')
            #print "reqinfo5",req.headers
            u = urllib2.urlopen(req)
            content=u.read()
            self.logger.info(content)
            result = json.loads(content)
            self.psessionid=result['result']['psessionid']
            self.vfwebqq=result['result']['vfwebqq']
            self.index=result['result']['index']
            self.port=result['result']['port']
            self.cookie['psessionid']=self.psessionid
            self.cookie['vfwebqq']=self.vfwebqq
            self.cookie['index']=self.index
            self.cookie['port']=self.port
            self.cookie['ptwebqq']=self.ptwebqq
            self.cookie['']=self
            self.logger.info('%s%s%s',result['retcode'],result['result']['vfwebqq'], result['result']['psessionid'])
            return True
        except Exception,e:
            self.logger.exception("Exception:%s",e)
            return False
    def poll(self):
        try:
            url='http://d.web2.qq.com/channel/poll2'
            #self.logger.info(url)
            data=collections.OrderedDict()
            data['r']='{"clientid":"%s","psessionid":"%s","key":0,"ids":[]}'%(self.clientid,self.psessionid)
            data['clientid']=self.clientid
            data['psessionid']=self.psessionid
            data=urllib.urlencode(data)
            #print "data:",data
            req=urllib2.Request(url,data)
            #req.add_header('Cookie',cs)
            req.add_header('Referer', 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=2')
            req.add_header('ContentType', 'application/x-www-form-urlencoded')
            res= urllib2.urlopen(req)
            result=json.loads(res.read())
            #print 'get message',result
            return result
        except Exception,e:
            self.logger.exception("Exception:%s",e)
        pass
    def run(self):
            try:
                while True :
                    #self.getMessageTip()
                    message=self.poll()
                    self.process_message(message)
                    time.sleep(1)  
            except Exception,e:
                self.logger.exception("Exception:%s",e)
    def process_message(self,message):
        try:
            #switch(message['retcode']):
            self.logger.info('process_message:%s',message)
            retcode=message['retcode']
            #print "retcode:",retcode
            #print 'retcode:',retcode
            self.mssage_action[retcode](message)
            #print 'after call'
        except Exception,e:
            self.logger.exception("Exception:%s",e)
        pass
    def process_result(self,message):
        try:
            #print self.__class__,self.__name,__file__
            #print 'process_result'
            result=message['result']
            for msg in result:
                poll_type=msg['poll_type']
                #print 'poll_type:%s'%poll_type
                self.poll_type_action[poll_type](msg['value'])
        except Exception,e:
            self.logger.exception("Exception:%s",e)
        pass
    def process_group_message(self,message):
        print '#group_message:',message
        print 'content:',message['content']
        for c in message['content']:
            print 'c:',c
        pass
    def process_shake_message(self,message):
        print '#shake_message:',message
        pass
    def process_buddy_message(self,message):
        print '#buddy_message:',message
        
        pass
    def process_input_notify(self,message):
        print '#input_notify:',message
        
        pass
    
    def process_errmsg(self,message):
        #print 'errmsg:',message
        pass
    def process_update_vfwebqq(self,message):
        self.vfwebqq=message['p']
        pass
    def get_group_info_ext2(self,gcode):
        url='http://s.web2.qq.com/api/get_group_info_ext2?gcode=%s&cb=undefined&vfwebqq=%s&t=%s'%(gcode,self.vfwebqq,time.time())
        self.logger.info(url)
        req=urllib2.Request(url)
        #req.add_header('Cookie',cs)
        req.add_header('Referer', 'http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=3')
        res= urllib2.urlopen(req)
        result=json.loads(res.read())
        self.logger.info('get_group_info_ext2:%s',result)
        return result
    def get_user_friends2(self):
        url='http://s.web2.qq.com/api/get_user_friends2'
        self.logger.info(url)
        data=collections.OrderedDict()
       
        hash=self.get_hash(self.uin,self.ptwebqq)
        self.logger.info("uin:%s ptwebqq:%s hash:%s",self.uin,self.ptwebqq,hash)
        data['r']='{"h":"hello","hash":"%s","vfwebqq":"%s"}'%(hash,self.vfwebqq)
        data=urllib.urlencode(data)
        self.logger.info("data:%s",data)
        req=urllib2.Request(url,data)
        #req.add_header('Cookie',cs)
        req.add_header('Referer', 'http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=1')
        req.add_header('ContentType', 'application/x-www-form-urlencoded')
        res= urllib2.urlopen(req)
        result=json.loads(res.read())
        self.logger.info('get_user_friends2:%s',result)
        return result
    def get_group_name_list_mask2(self):
        url='http://s.web2.qq.com/api/get_group_name_list_mask2'
        self.logger.info(url)
        data=collections.OrderedDict()
        data['r']='{"vfwebqq":"%s"}'%(self.vfwebqq)
        data=urllib.urlencode(data)
        self.logger.info("data:%s",data)
        req=urllib2.Request(url,data)
        #req.add_header('Cookie',cs)
        req.add_header('Referer', 'http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=3')
        req.add_header('ContentType', 'application/x-www-form-urlencoded')
        res= urllib2.urlopen(req)
        result=json.loads(res.read())
        self.logger.info('get_group_name_list_mask2:%s',result)
        return result
    def get_online_buddies2(self):
        url='http://d.web2.qq.com/channel/get_online_buddies2?clientid=%s&psessionid=%s&t=%s'%(self.clientid,self.psessionid,time.time())
        self.logger.info(url)
        req=urllib2.Request(url)
        #req.add_header('Cookie',cs)
        req.add_header('Referer', 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=2')
        res= urllib2.urlopen(req)
        result=json.loads(res.read())
        self.logger.info('get_online_buddies2:%s',result)
        return result
    def get_friend_info2(self,uin):
        url='http://s.web2.qq.com/api/get_friend_info2?tuin=%s&verifysession=&code=&vfwebqq=%s&t=%s'%(uin,self.vfwebqq,time.time())
        self.logger.info(url)
        req=urllib2.Request(url)
        #req.add_header('Cookie',cs)
        req.add_header('Referer', 'http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=3')
        res= urllib2.urlopen(req)
        result=json.loads(res.read())
        self.logger.info('get_friend_info2:%s',result)
        return result
    def get_single_long_nick2(self,uin):
        url='http://s.web2.qq.com/api/get_friend_info2?tuin=%s&verifysession=&code=&vfwebqq=%s&t=%s'%(uin,self.vfwebqq,time.time())
        self.logger.info(url)
        req=urllib2.Request(url)
        #req.add_header('Cookie',cs)
        req.add_header('Referer', 'http://s.web2.qq.com/proxy.html?v=20110412001&callback=1&id=3')
        res= urllib2.urlopen(req)
        result=json.loads(res.read())
        self.logger.info('get_single_long_nick2:%s',result)
        return result
    def get_recent_list2(self):
        url='http://d.web2.qq.com/channel/get_recent_list2'
        self.logger.info(url)
        data=collections.OrderedDict()
        data['r']='{"vfwebqq":"%s","clientid":"%s","psessionid":"%s"}'%(self.ptwebqq,self.clientid,self.psessionid)
        data=urllib.urlencode(data)
        self.logger.info("data:%s",data)
        req=urllib2.Request(url,data)
        #req.add_header('Cookie',cs)
        req.add_header('Referer', 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=2')
        req.add_header('ContentType', 'application/x-www-form-urlencoded')
        res= urllib2.urlopen(req)
        result=json.loads(res.read())
        self.logger.info('get_recent_list2:%s',result)
        return result
    def get_hash(self,a,e):
        c = []
        for i in a:
            c.append(int(i))
        b = 0
        k = -1
        for i in c:
            b += i
            b %= len(e)
            f = 0
            if (b + 4 > len(e)):
                h = 0
                g = 4 + b - len(e)
                while  h < 4:
                    if h < g:
                        f |= (ord(e[b + h]) & 255) << (3 - h) * 8
                    else:
                        f |= (ord(e[h - g]) & 255) << (3 - h) * 8
                    h += 1
            else:
                h = 0
                while h < 4:
                    f |= (ord(e[b + h]) & 255) << (3 - h) * 8
                    h += 1
            #print i,f
            k ^= f
        c = [k >> 24 & 255,k >> 16 & 255,k >> 8 & 255,k & 255]
        k = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"]
        d = ""
        b = 0
        while b < len(c):
            d += k[c[b] >> 4 & 15]
            d += k[c[b] & 15]
            b += 1
        return d
    def get_message_tip(self):
        url='http://web.qq.com/web2/get_msg_tip?uin=&tp=2&id=0&retype=1&rc=0&lv=3&t=%s'%(time.time())
        req=urllib2.Request(url)
        #req.add_header('Referer', loginUrl)
        #req.add_header('Host','ptlogin4.web2.qq.com')
        res= urllib2.urlopen(req)
        result=json.loads(res.read())
        self.logger.info('get_message_tip',result)
        return result
    def send_buddy_msg2(self,to_uin,content):
        url='http://d.web2.qq.com/channel/send_buddy_msg2'
        self.logger.info(url)
        data=collections.OrderedDict()
        data['r']='{"to":%s,"face":0,"content":"[\\"%s\\",[\\"font\\",{\\"name\\":\\"宋体\\",\\"size\\":\\"10\\",\\"style\\":[0,0,0],\\"color\\":\\"000000\\"}]]","msg_id":%s,"clientid":"%s","psessionid":"%s"}'%(to_uin,content,str(self.msg_id),self.clientid,self.psessionid)
        data['clientid']=self.clientid
        data['psessionid']=self.psessionid
        self.msg_id=self.msg_id+1
        data=urllib.urlencode(data)
        self.logger.info("data:",data)
        req=urllib2.Request(url,data)
        #req.add_header('Cookie',cs)
        req.add_header('Referer', 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=2')
        req.add_header('ContentType', 'application/x-www-form-urlencoded')
        res= urllib2.urlopen(req)
        result=json.loads(res.read())
        self.logger.info('send_buddy_msg2:%s',result)
        return result
    def send_qun_msg2(self,group_uin,content):
        url='http://d.web2.qq.com/channel/send_qun_msg2'
        self.logger.info(url)
        data=collections.OrderedDict()
        data['r']='{"group_uin":%s,"content":"[\\"%s\\",[\\"font\\",{\\"name\\":\\"宋体\\",\\"size\\":\\"10\\",\\"style\\":[0,0,0],\\"color\\":\\"000000\\"}]]","msg_id":%s,"clientid":"%s","psessionid":"%s"}'%(group_uin,content,str(self.msg_id),self.clientid,self.psessionid)
        data['clientid']=self.clientid
        data['psessionid']=self.psessionid
        self.msg_id=self.msg_id+1
        data=urllib.urlencode(data)
        self.logger.info("data:",data)
        req=urllib2.Request(url,data)
        #req.add_header('Cookie',cs)
        req.add_header('Referer', 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=3')
        req.add_header('ContentType', 'application/x-www-form-urlencoded')
        res= urllib2.urlopen(req)
        result=json.loads(res.read())
        self.logger.info('send_qun_msg2:%s',result)
        return result
    def getlog(self,uin,type):#singlemask groupmask
        if type=='0' :
            type='singlemask'
        elif type=='1':
            type='groupmask'
        url='http://tj.qstatic.com/getlog?qqweb2=%s$%s$bottom$send&t=%s'%(type,uin,time.time())
        self.logger.info(url)
        req=urllib2.Request(url)
        #req.add_header('Referer', loginUrl)
        #req.add_header('Host','ptlogin4.web2.qq.com')
        u=urllib2.urlopen(req)
        content=u.read()
        self.logger.info(u.info())
        self.logger.info(self.cookies)
        self.logger.info(content)
    def input_notify2(self,to_uin):
        url='http://d.web2.qq.com/channel/input_notify2?to_uin=%s&clientid=%s&psessionid=%s&t=%s'%(to_uin,self.clientid,self.psessionid,time.time())
        self.logger.info(url)
        req=urllib2.Request(url)
        #req.add_header('Cookie',cs)
        req.add_header('Referer', 'http://d.web2.qq.com/proxy.html?v=20110331002&callback=1&id=2')
        res= urllib2.urlopen(req)
        result=json.loads(res.read())
        self.logger.info('get_online_buddies',result)
    def encode_pwd(self,password,code,verifycode):
        ctxt = PyV8.JSContext()
        ctxt.enter()
        #f = open(os.getcwd()+ './encodePass.js', 'r')
        f = open(os.getcwd()+ './comm.js', 'r')
        ctxt.eval(f.read())
        f.close()
        funsrc='encode_pwd(\''+password+'\',\''+code+'\',\''+verifycode+'\')'
        #funsrc="passwordEncoding(\"" + number + "\",\"" + verifycodehex+ "\",\"" + verifycode.upper() + "\");"
        self.logger.info( funsrc)
        self.logger.info( ctxt.eval(funsrc))
        return ctxt.eval(funsrc)
        #print ctxt.eval('passwordEncoding(\''+uin+'\',\''+verify+'\',\''+verifycodehex+'\')')
        #return ctxt.eval('passwordEncoding(\''+uin+'\',\''+verify+'\',\''+verifycodehex+'\')')
    def getEncPass(self,q, p, v):
        m = md5.new(p).digest() + ("%0.16X" % q).decode('hex')
        return md5.new(md5.new(m).hexdigest().upper() + v.upper()).hexdigest().upper()
    def get_match(self,content,pattern):
        reObj=re.compile(pattern)
        allMatch=reObj.findall(content)
        if allMatch:
            return allMatch[0]
        else:
            self.logger.info("no fount:"+pattern)
            return ''
    def get_match_all(self,content,pattern):
        reObj=re.compile(pattern)
        allMatch=reObj.search(content)
        if allMatch:
            #print "fount:",allMatch.group(1)
            return allMatch
        else:
            self.logger.info("no fount:"+pattern)
            return ''
    def get_login_sig(self,content):
        str='g_login_sig=encodeURIComponent\\("(.*?)"\\);'
        reObj=re.compile(str)
        allMatch=reObj.findall(content)
        if allMatch:
            #print "fount"
            loginhash=allMatch[0]
            #print loginhash
            return loginhash
        else:
            self.logger.info("no fount login sig")
            return ''
    
#===============================================================================
# cookies=cookielib.CookieJar()
# 
# class HTTPCookieRedirectHandler(urllib2.HTTPRedirectHandler):
#     __cookie_flag = 'Set-Cookie: '
#         
#     @staticmethod
#     def __find_cookie(headers):
#         for msg in headers:
#             if msg.find(HTTPCookieRedirectHandler.__cookie_flag) != -1:
#                 return msg.replace(HTTPCookieRedirectHandler.__cookie_flag, '')
#  
#             return ''
#  
#     def http_error_301(self, req, fp, code, msg, httpmsg):
#         cookie = HTTPCookieRedirectHandler.__find_cookie(httpmsg.headers)
#         if cookie != '':
#             req.add_header("Cookie", cookie)
#         return urllib2.HTTPRedirectHandler.http_error_301(self, req, fp, code, msg, httpmsg)
#     def http_error_3021(self, req, fp, code, msg, httpmsg):
#         cookie = HTTPCookieRedirectHandler.__find_cookie(httpmsg.headers)
#         if cookie != '':
#             req.add_header("Cookie", cookie)
#         return urllib2.HTTPRedirectHandler.http_error_301(self, req, fp, code, msg, httpmsg)
# 
# class MyHTTPRedirectHandler(urllib2.HTTPRedirectHandler):
#     def http_error_302(self, req, fp, code, msg, headers):
#         print "Cookie Manip Right Here=="
#         print "===================",headers.headers
#         cookies.add_cookie_header(req)
#         cs = ['%s=%s' % (c.name, c.value) for c in cookies]
#         req.add_header('Cookie', cookies)
#         print "++++++++++++++++++",cs
#         #headers.headers['ftttttttttt']='aaaaaaaaaaa'
#         print "===================11",headers.headers
#          
#         return urllib2.HTTPRedirectHandler.http_error_302(self, req, fp, code, msg, headers)
#         #http_error_301 = http_error_303 = http_error_307 = http_error_302
#     def http_error_301(self, req, fp, code, msg, headers):
#         print "Cookie Manip Right Here"
#         print "===================",headers.headers
#         cookies.add_cookie_header(req)
#         #print headers.headers
#         cs = ['%s=%s' % (c.name, c.value) for c in cookies]
#          
#         print "-------------------",cs
#         return urllib2.HTTPRedirectHandler.http_error_301(self, req, fp, code, msg, headers)
#===============================================================================

#opener=urllib2.build_opener(MyHTTPRedirectHandler,urllib2.HTTPCookieProcessor(cookies))
#opener=urllib2.build_opener(HTTPCookieRedirectHandler,urllib2.HTTPCookieProcessor(cookies))