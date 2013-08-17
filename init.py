# -*- coding: UTF-8 -*-  
'''
Created on 2013-8-17

@author: rootntsd@gmail.com
'''
import eqq
import eqq_machine
from eqq import EqqClient
from eqq_machine import EqqMachine


def test_eqq(uin,pwd):
    eqq=EqqClient()
    eqq.set_account(uin, pwd)
    eqq.login()
    eqq.get_friend_info2(uin)
    eqq.get_user_friends2()
    eqq.get_group_name_list_mask2()
    eqq.get_online_buddies2()
    eqq.get_recent_list2()
    eqq.get_group_info_ext2('523413439')
    #eqq.send_buddy_msg2('2699969892', '�ڸ���ѽ!')
    #eqq.send_qun_msg2('268512380', '�ڸ���ѽ')
    #eqq.getlog('268512380','groupmask')
    #print "hash:",eqq.get_hash(uin,'892d42b6b4ecfbd7ec9dcf67ccc2b51fe714c31ab1a983b22702c1256c593a7f')
    eqq.start()

if __name__=="__main__":
    try:
        uin='2669697798'
        pwd='you password'
        em=EqqMachine(uin,pwd)
        em.init()
        em.run()
        pass
    except Exception,e:
        print e
