# -*- coding: UTF-8 -*-  
import eqq
import argparse
from eqq import EqqClient



class EqqMachine(object):
    def __init__(self,uin,pwd):
        self.eqq=EqqClient()
        self.eqq.set_output()
        self.uin=uin
        self.pwd=pwd
        self.eqq.set_account(uin,pwd)
        self.eqq.login()
        self.eqq.get_friend_info2(uin)
        self.eqq.get_user_friends2()
        self.eqq.get_group_name_list_mask2()
        self.eqq.get_online_buddies2()
        self.eqq.get_recent_list2()
        
        self.groups
    def init(self):
        self.set_message_process()
        self.eqq.start()
    def run(self):
        while True:
            cmd=raw_input("eqq#:")
            self.pase_command(cmd)
        
    def pase_command(self,command):
        pass
    def set_message_process(self):
        self.eqq.set_poll_type_action('shake_message',self.process_shake_message)
        self.eqq.set_poll_type_action('group_message',self.process_group_message)
    def process_shake_message(self,message):
        print '#shake_message:',message
        pass
    def process_group_message(self,message):
        print '#group_message:',message
        print 'content:',message['content']
        for c in message['content']:
            print 'c:',c
        pass   
        
        
        