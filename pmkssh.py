# -*- coding: utf-8 -*-

import tkinter
import tkinter.ttk
import tkinter.filedialog
from tkMessageBox import *
from ScrolledText import ScrolledText #文本滚动条
import threading

import sqlite3 as sql
import socket
import os
import uuid
import time
import xlwt

import base64
from icon import img

from pyDes import *
from binascii import unhexlify as unhex
from binascii import b2a_hex, a2b_hex

import paramiko


kk = triple_des(unhex("201809229378ABCDEF9921ABCDEF9921"))
hostname = socket.gethostname()
uid = str(uuid.uuid3(uuid.NAMESPACE_DNS, hostname).hex[-12:])


#http://www.network-science.de/ascii/
#standard
figlet = '''
 ____  _____    _             _ _       
|  _ \|  ___|__| |_ _   _  __| (_) ___  
| | | | |_ / __| __| | | |/ _` | |/ _ \ 
| |_| |  _|\__ \ |_| |_| | (_| | | (_) |
|____/|_|  |___/\__|\__,_|\__,_|_|\___/ 
    
'''


def readme():
    showinfo("软件说明","\n\
V0.06\n\
增加su-root再执行命令功能\n\
在su-root密码框输入密码则开启\n\
V0.05\n\
增加生成服务器基本信息导出到xls\n\
V0.04\n\
增加服务器信息列排序\n\
增加导入服务器信息\n\
V0.03\n\
增加文件上传功能\n\
增加文件下载功能\n\
\n\
**********************************\n\
\n\
以轻量级为初衷的远程管理工具\n\
用于批量远程管理服务器\n\
基于paramiko使用python开发\n\
\n\
1.通过输入服务器信息加密保存到数据文件\n\
2.数据文件绑定电脑安全无泄漏\n\
3.单选或多选服务器后输入命令点击运行\n\
4.如填写单行命令,则命令文件不执行\n\
5.导入服务器信息文件格式\nip,port,user,pwd以TAB分隔\n\
\n\
已知BUG\n\
程序在执行时会出现未响应情况,不要中断,执行命令会有30秒超时\n\
打开后中文乱码,请在系统字体中开启Fixedsys常规字体\n\
上传或下载选择路径中不能有中文名称\n\
运行后只显示LOGO原因,程序与数据文件连接超时,重新打开软件即可\n\
")

def author():
    showinfo("关于","\n\
Neusoft-DF\n\
")

def createtabel():
    conn = sql.connect('pmkssh.db')
    c = conn.cursor()
    c.execute("CREATE TABLE serinfo(iid integer PRIMARY KEY autoincrement, \
                                    ip VARCHAR(50) NOT NULL, \
                                    port int(50) NOT NULL, \
                                    user varchar(50) NOT NULL, \
                                    pwd varchar(50) DEFAULT NULL, \
                                    status int(1) DEFAULT NULL, \
                                    mark int(1) DEFAULT NULL)")
    c.execute("CREATE TABLE email(emailid varchar primary key)")
    c.execute("CREATE TABLE hostuid(uuid varchar primary key)")
    c.execute("INSERT INTO hostuid values(?)",(uid,))
    conn.commit()
    c.close()

def selectfile():
    filename = tkinter.filedialog.askopenfilename()
    path.set(filename)

def selectuppath():
    uppath_ = tkinter.filedialog.askdirectory()
    uppath.set(uppath_)

def selectdownpath():
    downpath_ = tkinter.filedialog.askdirectory()
    downpath.set(downpath_)

def selectimpserfile():
    impserfile_ = tkinter.filedialog.askopenfilename()
    impserfile.set(impserfile_)

def impserver():
    importserverfile = impser1filefield.get()
    if importserverfile:
        conn = sql.connect('pmkssh.db')
        c = conn.cursor()
        serverlist = open(str(importserverfile), "r")
        for line in serverlist:
            #取IP、用户名、密码
            ip=line.split()[0]
            print 'import: ',ip
            port=line.split()[1]
            username=line.split()[2]
            password=line.split()[3]
            desip = kk.encrypt(ip, padmode=PAD_PKCS5)
            desport = kk.encrypt(port, padmode=PAD_PKCS5)
            desuser = kk.encrypt(username, padmode=PAD_PKCS5)
            despwd = kk.encrypt(password, padmode=PAD_PKCS5)
            desip = b2a_hex(desip)
            desport = b2a_hex(desport)
            desuser = b2a_hex(desuser)
            despwd = b2a_hex(despwd)
            c.execute("INSERT INTO serinfo values(NULL,?,?,?,?,?,?)",(desip,desport,desuser,despwd,'0','0'))
            conn.commit()
            viewmsg()
            time.sleep(0.001)
        c.close()
    else:
        msg1["text"] = "请选择服务器信息文件"

def gosel(event):
    selectnum = []
    select=tree.selection()
    for idx  in select:
        selnum = tree.item(idx,'values')[0]
        selectnum.append(selnum)
    text.insert(tkinter.END,u'共选择服务器台数: '+str(len(selectnum))+'\n')
    text.insert(tkinter.END,u'已选择服务器编号: '+str(selectnum)+'\n')
    text.see(tkinter.END)
    time.sleep(0.001)
    msg1["text"] = ""
    print u'共选择服务器台数: '+str(len(selectnum))
    print u'已选择服务器编号: '+str(selectnum)
    return selectnum

def treeview_sort_column(tv, col, descending):
    """sort tree contents when a column header is clicked on"""
    # grab values to sort
    data = [(tv.set(k, col), k) for k in tv.get_children('')]
    # if the data to be sorted is numeric change to float
    #data =  change_numeric(data)
    # now sort the data in place
    data.sort(reverse=descending)
    # rearrange items in sorted positions
    for index, (val, k) in enumerate(data):
        tv.move(k, '', index)
    # reverse sort next time
    tv.heading(col, command=lambda col=col: treeview_sort_column(tv, col, int(not descending)))

def viewmsg():
    x = tree.get_children()
    for item in x:
        tree.delete(item)
    conn = sql.connect('pmkssh.db')
    c = conn.cursor()
    getuid = c.execute("SELECT * FROM hostuid ORDER BY uuid")
    for row in getuid:
        gotuid = str(row[0])
    if gotuid==uid:
        cntip = c.execute("SELECT count(ip) FROM serinfo")
        for row in cntip:
            cntnum = str(row[0])
        msg["text"] = "TOTAL: " + cntnum
        if row[0] == 0:
            msg1["text"] = "请增加服务器信息"
        else:
            msg1["text"] = "选择服务器->输入命令->点击运行"
        infomsg = c.execute("SELECT * FROM serinfo ORDER BY iid desc")
        for row in infomsg:
            tree.insert("",0,values = (row[0], kk.decrypt(a2b_hex(str(row[1])), padmode=PAD_PKCS5), kk.decrypt(a2b_hex(str(row[2])), padmode=PAD_PKCS5), \
                                       kk.decrypt(a2b_hex(str(row[3])), padmode=PAD_PKCS5), '******'))
    c.close()


def additem():
    ip = ipfield.get()
    port = portfield.get()
    user = userfield.get()
    pwd = pwdfield.get()
    desip = kk.encrypt(ip, padmode=PAD_PKCS5)
    desport = kk.encrypt(port, padmode=PAD_PKCS5)
    desuser = kk.encrypt(user, padmode=PAD_PKCS5)
    despwd = kk.encrypt(pwd, padmode=PAD_PKCS5)
    desip = b2a_hex(desip)
    desport = b2a_hex(desport)
    desuser = b2a_hex(desuser)
    despwd = b2a_hex(despwd)
    if ip == "":
        msg1["text"] = "请填写服务器IP"
        print (u"请填写服务器IP")
    else:
        conn = sql.connect('pmkssh.db')
        c = conn.cursor()
        c.execute("INSERT INTO serinfo values(NULL,?,?,?,?,?,?)",(desip,desport,desuser,despwd,'0','0'))
        conn.commit()
        c.close()
        ipfield.delete(0,tkinter.END)
        portfield.delete(0,tkinter.END)
        userfield.delete(0,tkinter.END)
        pwdfield.delete(0,tkinter.END)
        viewmsg()


def delitem():
    ip = ipfield.get()
    desip = kk.encrypt(ip, padmode=PAD_PKCS5)
    desip = b2a_hex(desip)
    user = userfield.get()
    desuser = kk.encrypt(user, padmode=PAD_PKCS5)
    desuser = b2a_hex(desuser)
    if ip == "" or user == "":
        msg1["text"] = "请填写服务器IP和USER"
        print (u"请填写服务器IP和USER")
    else:
        conn = sql.connect('pmkssh.db')
        c = conn.cursor()
        c.execute("DELETE FROM serinfo where ip=? and user=?",(desip,desuser,))
        conn.commit()
        c.close()
        ipfield.delete(0,tkinter.END)
        portfield.delete(0,tkinter.END)
        userfield.delete(0,tkinter.END)
        pwdfield.delete(0,tkinter.END)
        viewmsg()


if not os.path.exists('pmkssh.db'):
    createtabel()

def checkreport():
    conn = sql.connect('pmkssh.db')
    c = conn.cursor()
    getuid = c.execute("SELECT * FROM hostuid ORDER BY uuid")
    for row in getuid:
        gotuid = str(row[0])
    if gotuid==uid:
        selectserver = gosel('null')
        if selectserver:
            column=['ip','主机名','版本','系统','CPU','核数','内存','swap','存储','网卡','防火墙','SELINUX','NTPD','时间']
            wb = xlwt.Workbook(encoding='gbk',style_compression=0)
            ws = wb.add_sheet('SERVERINFO',cell_overwrite_ok=True)
            for i in range(0,len(column)):
                ws.write(0,i,column[i].decode('utf8'))
            wsresult = []
            wsrow = 0
            for linenum in selectserver:
                serinfomsg = c.execute("SELECT * FROM serinfo where iid=? ORDER BY iid desc",(linenum,))
                for row in serinfomsg:
                    ip = kk.decrypt(a2b_hex(str(row[1])), padmode=PAD_PKCS5)
                    port = kk.decrypt(a2b_hex(str(row[2])), padmode=PAD_PKCS5)
                    username = kk.decrypt(a2b_hex(str(row[3])), padmode=PAD_PKCS5)
                    password = kk.decrypt(a2b_hex(str(row[4])), padmode=PAD_PKCS5)

                    try:
                        ssh=paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(hostname=ip,port=port,username=username,password=password)

                        #cat /proc/cpuinfo| grep "cpu cores"| uniq
                        #dmidecode -s processor-version
                        #fdisk -l |grep "Disk /dev/s" |sort
                        #lsblk
                        #grep "core id" /proc/cpuinfo
                        #/sbin/ifconfig |grep -w inet|awk '{print $2}'|awk -F '/' '{print $1}'
                        #systemctl status firewalld |grep 'Active'|awk -F ': ' '{print $2}'
                        #systemctl status ntpd |grep Active|awk -F ': ' '{print $2}'
                        #grep 'model name' /proc/cpuinfo|sort -u|awk -F ': ' '{print $2}'
                        #grep "core id" /proc/cpuinfo|sort -u|wc -l
                        #free -m |grep 'Mem' | awk '{print $2}'
                        
                        cmdlist = ['hostname','cat /etc/redhat-release','uname -a',"grep 'model name' /proc/cpuinfo|sort -u|awk -F ': ' '{print $2}'", \
                                   'grep "core id" /proc/cpuinfo|sort -u|wc -l',"free -h |grep 'Mem' | awk '{print $2}'", \
                                   "free -h |grep 'Swap' | awk '{print $2}'","lsblk","/sbin/ifconfig |grep -w inet|awk '{print $2}'|awk -F '/' '{print $1}'", \
                                   "systemctl status firewalld |grep 'Active'|awk -F ': ' '{print $2}'","/sbin/getenforce", \
                                   "systemctl status ntpd |grep Active|awk -F ': ' '{print $2}'","date"]

                        print('SERVER IP: %s\n' %(ip))
                        text.insert(tkinter.END, 'Server IP: '+ip+'\n\n')
                        text.see(tkinter.END)
                        time.sleep(0.001)
                        wsresult.append(str(ip))
                        #执行命令
                        for line in cmdlist:
                            #print('    Commond : '+line)
                            print('COMMOND: %s' %(line))
                            text.insert(tkinter.END, 'Commond: '+line+'\n')
                            text.see(tkinter.END)
                            time.sleep(0.001)
                            stdin,stdout,stderr=ssh.exec_command(line,timeout=30,get_pty=False)
                            resultline = stdout.read()
                            resultlineerr = stderr.read()
                            if resultline:
                                wsresult.append(resultline.decode('utf-8'))
                                
                                print('RESULT: \n%s' %(resultline))
                                text.insert(tkinter.END, 'Result: \n'+resultline+'\n')
                                text.see(tkinter.END)
                                time.sleep(0.001)
                            elif resultlineerr:
                                print('SERVER IP: %s\nCOMMOND: %s\n\n%s\n' %(ip, line, resultlineerr))
                                text.insert(tkinter.END, 'Server IP: '+ip+'\n'+'Commond: '+line+'\n'+resultlineerr+'\n')
                                text.see(tkinter.END)
                                time.sleep(0.001)
                        ssh.close()
                    except Exception, e1:
                        print '\n******\nConnect %s@%s timeout or Commond Error!\n******\n\n' %(username,ip)
                        text.insert(tkinter.END,'\n******\nConnect %s@%s timeout or Commond Error!\n******\n\n' %(username,ip))
                        text.see(tkinter.END)
                        time.sleep(0.001)
                        
            #print wsresult
            n = len(column)
            spwsresult = [wsresult[k:k+n] for k in range(0,len(wsresult),n)]
            
            for v in range(len(spwsresult)):
                wsrow = wsrow + 1
                for j in range(0,len(spwsresult[v])):
                    ws.write(wsrow,j,spwsresult[v][j])
            wb.save('server_info.xls')
        else:
            msg1["text"] = "请选择服务器"
            print (u"请选择服务器")

                        
def ssh_login(ip,port,username,password):
    try:
        #建立连接
        ssh=paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=ip,port=port,username=username,password=password)

        #打印分割符
        #print('    Server : '+ip)

        shellorder = shellfield.get()
        root_pwd = rootpwdfield.get()
        #root_pwd = 'abc.(OL<5tgb'
        #root_pwd = ''
                
        if shellorder:
            print('SERVER IP: %s\nCOMMOND: %s\n' %(ip, shellorder))
            text.insert(tkinter.END, 'Server IP: '+ip+'\n'+'Commond: '+shellorder+'\n')
            text.see(tkinter.END)
            time.sleep(0.001)
            
            if root_pwd:
                ssshh = ssh.invoke_shell(term='VT100')
                time.sleep(0.1)
                ssshh.send('su - \n')
                buff = ''
                while not buff.endswith('Password: '):
                    resp = ssshh.recv(65535).decode('utf-8')
                    buff += resp
                ssshh.send(root_pwd)
                ssshh.send('\n')
                buff = ''
                while not buff.endswith('# '):
                    resp = ssshh.recv(65535).decode('utf-8')
                    buff += resp
                    time.sleep(0.1)
                ssshh.send(shellorder)
                ssshh.send('\n')
                buff = ''
                while not buff.endswith('# '):
                    resp = ssshh.recv(65535).decode('utf-8')
                    buff += resp
                    time.sleep(0.1)
                result = buff
                if result:
                    print('RESULT: \n%s\n' %(result))
                    text.insert(tkinter.END, 'Result: \n'+result+'\n')
                    text.see(tkinter.END)
                    time.sleep(0.001)
                elif resulterr:
                    print('SERVER IP: %s\nCOMMOND: %s\n\n%s\n' %(ip, shellorder, resulterr))
                    text.insert(tkinter.END, 'Server IP: '+ip+'\n'+'Commond: '+shellorder+'\n'+resulterr+'\n')
                    text.see(tkinter.END)
                    time.sleep(0.001)
            else:
                stdin,stdout,stderr=ssh.exec_command(shellorder,timeout=30,get_pty=False)
                #except Exception, e1:
                    #print Exception
                #finally:
                    #print('commond timeout')
                    #text.insert(tkinter.END, 'Server IP: '+ip+'\n'+'Commond: '+shellorder+'\n'+'\ncommond timeout\n')
                    #text.see(tkinter.END)
                    #time.sleep(0.001)
                result = stdout.read()
                resulterr = stderr.read()
                if result:
                    print('RESULT: \n%s\n' %(result))
                    text.insert(tkinter.END, 'Result: \n'+result+'\n')
                    text.see(tkinter.END)
                    time.sleep(0.001)
                elif resulterr:
                    print('SERVER IP: %s\nCOMMOND: %s\n\n%s\n' %(ip, shellorder, resulterr))
                    text.insert(tkinter.END, 'Server IP: '+ip+'\n'+'Commond: '+shellorder+'\n'+resulterr+'\n')
                    text.see(tkinter.END)
                    time.sleep(0.001)
        else:
            cmdfile = filefield.get()
            if cmdfile:
                #读取命令文件
                cmdlist = open(str(cmdfile),"r")
                #执行命令
                for line in cmdlist:
                    #print('    Commond : '+line)
                    print('SERVER IP: %s\nCOMMOND: %s\n' %(ip, line))
                    text.insert(tkinter.END, 'Server IP: '+ip+'\n'+'Commond: '+line+'\n')
                    text.see(tkinter.END)
                    time.sleep(0.001)


                    if root_pwd:
                        ssshh = ssh.invoke_shell(term='VT100')
                        time.sleep(0.1)
                        ssshh.send('su - \n')
                        buff = ''
                        while not buff.endswith('Password: '):
                            resp = ssshh.recv(65535).decode('utf-8')
                            buff += resp
                        ssshh.send(root_pwd)
                        ssshh.send('\n')
                        buff = ''
                        while not buff.endswith('# '):
                            resp = ssshh.recv(65535).decode('utf-8')
                            buff += resp
                        ssshh.send(line)
                        ssshh.send('\n')
                        buff = ''
                        while not buff.endswith('# '):
                            resp = ssshh.recv(65535).decode('utf-8')
                            buff += resp
                        result = buff
                        if result:
                            print('RESULT: \n%s\n' %(result))
                            text.insert(tkinter.END, 'Result: \n'+result+'\n')
                            text.see(tkinter.END)
                            time.sleep(0.001)
                        elif resulterr:
                            print('SERVER IP: %s\nCOMMOND: %s\n\n%s\n' %(ip, line, resulterr))
                            text.insert(tkinter.END, 'Server IP: '+ip+'\n'+'Commond: '+line+'\n'+resulterr+'\n')
                            text.see(tkinter.END)
                            time.sleep(0.001)
                    else:
                        stdin,stdout,stderr=ssh.exec_command(line,timeout=30,get_pty=False)
                        result = stdout.read()
                        resulterr = stderr.read()
                        if result:
                            print('RESULT: \n%s\n' %(result))
                            text.insert(tkinter.END, 'Result: \n'+result+'\n')
                            text.see(tkinter.END)
                            time.sleep(0.001)
                        elif resulterr:
                            print('SERVER IP: %s\nCOMMOND: %s\n\n%s\n' %(ip, line, resulterr))
                            text.insert(tkinter.END, 'Server IP: '+ip+'\n'+'Commond: '+line+'\n'+resulterr+'\n')
                            text.see(tkinter.END)
                            time.sleep(0.001)
                cmdlist.close()
            else:
                msg1["text"] = "请输入命令或选择命令文件"
                print (u"请输入命令或选择命令文件")

        #关闭连接
        ssh.close()

    except Exception, e1:
        print '\n******\nConnect %s@%s timeout or Commond Error!\n******\n\n' %(username,ip)
        text.insert(tkinter.END,'\n******\nConnect %s@%s timeout or Commond Error!\n******\n\n' %(username,ip))
        text.see(tkinter.END)
        time.sleep(0.001)
   
def main():

    print figlet
    text.insert(tkinter.END,figlet+'\n')
    text.see(tkinter.END)
    time.sleep(0.001)

    conn = sql.connect('pmkssh.db')
    c = conn.cursor()
    getuid = c.execute("SELECT * FROM hostuid ORDER BY uuid")
    for row in getuid:
        gotuid = str(row[0])
    if gotuid==uid:
        selectserver = gosel('null')
        if selectserver:
            for linenum in selectserver:
                serinfomsg = c.execute("SELECT * FROM serinfo where iid=? ORDER BY iid desc",(linenum,))
                thread_list = []
                for row in serinfomsg:
                    ip = kk.decrypt(a2b_hex(str(row[1])), padmode=PAD_PKCS5)
                    port = kk.decrypt(a2b_hex(str(row[2])), padmode=PAD_PKCS5)
                    username = kk.decrypt(a2b_hex(str(row[3])), padmode=PAD_PKCS5)
                    password = kk.decrypt(a2b_hex(str(row[4])), padmode=PAD_PKCS5)

                    t = threading.Thread(target=ssh_login,args=(ip,port,username,password))
                    thread_list.append(t)
                for t in thread_list:
                    t.start()
                for t in thread_list:
                    t.join()

        else:
            msg1["text"] = "请选择服务器"
            print (u"请选择服务器")
    c.close()


def upfile():

    print figlet
    text.insert(tkinter.END,figlet+'\n')
    text.see(tkinter.END)
    time.sleep(0.001)

    conn = sql.connect('pmkssh.db')
    c = conn.cursor()
    getuid = c.execute("SELECT * FROM hostuid ORDER BY uuid")
    for row in getuid:
        gotuid = str(row[0])
    if gotuid==uid:
        selectserver = gosel('null')
        if selectserver:
            for linenum in selectserver:
                serinfomsg = c.execute("SELECT * FROM serinfo where iid=? ORDER BY iid desc",(linenum,))
                thread_list = []
                for row in serinfomsg:
                    ip = kk.decrypt(a2b_hex(str(row[1])), padmode=PAD_PKCS5)
                    port = kk.decrypt(a2b_hex(str(row[2])), padmode=PAD_PKCS5)
                    username = kk.decrypt(a2b_hex(str(row[3])), padmode=PAD_PKCS5)
                    password = kk.decrypt(a2b_hex(str(row[4])), padmode=PAD_PKCS5)

                    try:
                        #建立连接
                        t=paramiko.Transport((ip,int(port)))
                        t.connect(username=username,password=password)
                        sftp=paramiko.SFTPClient.from_transport(t)

                    except Exception, e1:
                        print u'连接%s@%s失败,检查网络或服务器信息' %(username,ip)
                        text.insert(tkinter.END,u'\n******\n连接%s@%s失败,检查网络或服务器信息' %(username,ip)+'\n******\n\n')
                        text.see(tkinter.END)
                        time.sleep(0.001)

                    
                    #本地路径
                    l_dirpath = up1pathfield.get()
                    l_dir=str(l_dirpath)
                    #远程路径
                    r_dirpath = up2pathfield.get()
                    r_dir=str(r_dirpath)

                    if l_dirpath and r_dirpath:
                        #分别上传文件
                        files=os.listdir(l_dir)
                        for f in files:
                            #本地路径+文件名
                            l_file=os.path.join(l_dir,f)
                            #远程路径+文件名
                            r_file=os.path.join(r_dir,f)
                            print('Server IP: '+ip+' '+'Upload:\n'+l_file+' ---> '+r_file+'\n')
                            text.insert(tkinter.END, 'Server IP: '+ip+' '+'Upload:\n'+l_file+' ---> '+r_file+'\n')
                            text.see(tkinter.END)
                            time.sleep(0.001)
                            #上传
                            sftp.put(l_file,r_file)         
                        t.close()
                    else:
                        msg1["text"] = "请选择上传路径和填写上传到路径"
        else:
            msg1["text"] = "请选择服务器"

def downfile():

    print figlet
    text.insert(tkinter.END,figlet+'\n')
    text.see(tkinter.END)
    time.sleep(0.001)

    conn = sql.connect('pmkssh.db')
    c = conn.cursor()
    getuid = c.execute("SELECT * FROM hostuid ORDER BY uuid")
    for row in getuid:
        gotuid = str(row[0])
    if gotuid==uid:
        selectserver = gosel('null')
        if selectserver:
            for linenum in selectserver:
                serinfomsg = c.execute("SELECT * FROM serinfo where iid=? ORDER BY iid desc",(linenum,))
                thread_list = []
                for row in serinfomsg:
                    ip = kk.decrypt(a2b_hex(str(row[1])), padmode=PAD_PKCS5)
                    port = kk.decrypt(a2b_hex(str(row[2])), padmode=PAD_PKCS5)
                    username = kk.decrypt(a2b_hex(str(row[3])), padmode=PAD_PKCS5)
                    password = kk.decrypt(a2b_hex(str(row[4])), padmode=PAD_PKCS5)

                    try:
                        #建立连接
                        t=paramiko.Transport((ip,int(port)))
                        t.connect(username=username,password=password)
                        sftp=paramiko.SFTPClient.from_transport(t)

                    except Exception, e1:
                        print u'连接%s@%s失败,检查网络或服务器信息' %(username,ip)
                        text.insert(tkinter.END,u'\n******\n连接%s@%s失败,检查网络或服务器信息' %(username,ip)+'\n******\n\n')
                        text.see(tkinter.END)
                        time.sleep(0.001)

                    #远程路径
                    r_dirpath = down2pathfield.get()
                    r_file=str(r_dirpath)

                    #本地路径
                    l_dirpath = down1pathfield.get()
                    l_dir=str(l_dirpath)


                    if l_dirpath and r_dirpath:
                        os.chdir(l_dir)
                            
                        if os.path.exists(ip) != True:
                            os.mkdir(ip)
                        l_dir=os.path.join(l_dir,ip)
                        #分别下载文件
                        #for r_file in filelist:
                            #r_file=r_file.strip('\n')
                        l_file=os.path.join(l_dir,os.path.basename(r_file))
                        print('Server IP: '+ip+' '+'Download:\n'+r_file+' ---> '+l_file+'\n')
                        text.insert(tkinter.END, 'Server IP: '+ip+' '+'Download:\n'+r_file+' ---> '+l_file+'\n')
                        text.see(tkinter.END)
                        time.sleep(0.001)
                        #下载
                        sftp.get(r_file,l_file)
                        
                        t.close()
                    else:
                        msg1["text"] = "请选择下载路径和填写文件名"
        else:
            msg1["text"] = "请选择服务器"


root=tkinter.Tk()
root.title('Neusoft Tools v0.06')  #窗口标题
tmp = open("tmp.ico","wb+")
tmp.write(base64.b64decode(img))
tmp.close()
root.iconbitmap("tmp.ico")
os.remove("tmp.ico")
root.geometry('+600+100')#窗口呈现位置

menubar = tkinter.Menu(root)
menubar.add_cascade(label = "软件说明",command = readme)
menubar.add_cascade(label = "关于",command = author)

label1 = tkinter.ttk.Label(root,text = "IP: ")
ipfield = tkinter.ttk.Entry(root)
label2 = tkinter.ttk.Label(root,text = "PORT: ")
portfield = tkinter.ttk.Entry(root)
label3 = tkinter.ttk.Label(root,text = "USER: ")
userfield = tkinter.ttk.Entry(root)
label4 = tkinter.ttk.Label(root,text = "PWD: ")
pwdfield = tkinter.ttk.Entry(root)
pwdfield['show'] = '*'
label5 = tkinter.ttk.Label(root,text = "CMD: ")
shellfield = tkinter.ttk.Entry(root, width = 70)

addbtn = tkinter.ttk.Button(root,text = "增加",command = additem)
flushbutn = tkinter.ttk.Button(root,text = "刷新",command = viewmsg)
delbtn = tkinter.ttk.Button(root,text = "删除",command = delitem)

msg = tkinter.ttk.Label(root,text = '')

#上传
uppath = tkinter.StringVar()
up1file = tkinter.ttk.Label(root,text = 'Upload: ')
up1file.grid(row = 9,column = 0)
up1pathfield = tkinter.ttk.Entry(root, textvariable = uppath)
up1pathfield.grid(row = 9,column = 1)
up1btn = tkinter.ttk.Button(root,text='选择目录',command=selectuppath)
up1btn.grid(row = 9,column = 4)

up2file = tkinter.ttk.Label(root,text = 'Upload to: ')
up2file.grid(row = 10,column = 0)
up2pathfieldtext = '/tmp/'
up2pathfieldset = tkinter.StringVar()
up2pathfieldset.set(up2pathfieldtext)
up2pathfield = tkinter.ttk.Entry(root, textvariable = up2pathfieldset)
up2pathfield.grid(row = 10,column = 1)
up2btn = tkinter.ttk.Button(root,text='上传目录',command=upfile)
up2btn.grid(row = 10,column = 4)

sv = tkinter.ttk.Separator(root,orient=tkinter.VERTICAL)
sv.grid(row = 9,column = 2,rowspan=2,sticky = "ns")
sv = tkinter.ttk.Separator(root,orient=tkinter.VERTICAL)
sv.grid(row = 9,column = 3,rowspan=2,sticky = "ns")

sh = tkinter.ttk.Separator(root, orient=tkinter.HORIZONTAL)
sh.grid(row=11,column=0,columnspan=5,sticky="we")
sh = tkinter.ttk.Separator(root, orient=tkinter.HORIZONTAL)
sh.grid(row=12,column=0,columnspan=5,sticky="we")

#下载
downpath = tkinter.StringVar()
down1file = tkinter.ttk.Label(root,text = 'Download: ')
down1file.grid(row = 13,column = 0)
down1pathfield = tkinter.ttk.Entry(root, textvariable = downpath)
down1pathfield.grid(row = 13,column = 1)
down1btn = tkinter.ttk.Button(root,text='选择目录',command=selectdownpath)
down1btn.grid(row = 13,column = 4)

down2file = tkinter.ttk.Label(root,text = 'Filename: ')
down2file.grid(row = 14,column = 0)
down2pathfieldtext = '/tmp/test.txt'
down2pathfieldset = tkinter.StringVar()
down2pathfieldset.set(down2pathfieldtext)
down2pathfield = tkinter.ttk.Entry(root, textvariable = down2pathfieldset)
down2pathfield.grid(row = 14,column = 1)
down2btn = tkinter.ttk.Button(root,text='下载文件',command=downfile)
down2btn.grid(row = 14,column = 4)

sv = tkinter.ttk.Separator(root,orient=tkinter.VERTICAL)
sv.grid(row = 13,column = 2,rowspan=2,sticky = "ns")
sv = tkinter.ttk.Separator(root,orient=tkinter.VERTICAL)
sv.grid(row = 13,column = 3,rowspan=2,sticky = "ns")

sh = tkinter.ttk.Separator(root, orient=tkinter.HORIZONTAL)
sh.grid(row=15,column=0,columnspan=5,sticky="we")
sh = tkinter.ttk.Separator(root, orient=tkinter.HORIZONTAL)
sh.grid(row=16,column=0,columnspan=5,sticky="we")

#root password
rootpwd = tkinter.ttk.Label(root,text = 'Root PWD: ')
rootpwd.grid(row = 17,column = 0)
rootpwdfield = tkinter.ttk.Entry(root)
rootpwdfield.grid(row = 17,column = 1)
rootpwdfield['show'] = '*'
rootpwd1 = tkinter.ttk.Label(root,text = 'su - root')
rootpwd1.grid(row = 17,column = 4)

#命令文件
path = tkinter.StringVar()
lb = tkinter.ttk.Label(root,text = 'Multi CMD: ')
lb.grid(row = 18,column = 0)
btn = tkinter.ttk.Button(root,text='选择文件',command=selectfile)
btn.grid(row = 18,column = 4)
filefield = tkinter.ttk.Entry(root, textvariable = path)
filefield.grid(row = 18,column = 1)

sv = tkinter.ttk.Separator(root,orient=tkinter.VERTICAL)
sv.grid(row = 17,column = 2,rowspan=2,sticky = "ns")
sv = tkinter.ttk.Separator(root,orient=tkinter.VERTICAL)
sv.grid(row = 17,column = 3,rowspan=2,sticky = "ns")

#导入服务器信息
impserfile = tkinter.StringVar()
impser1file = tkinter.ttk.Label(root,text = 'Import Server: ')
impser1file.grid(row = 0,column = 7)
impser1filefield = tkinter.ttk.Entry(root, textvariable = impserfile)
impser1filefield.grid(row = 0,column = 8)
impser1btn = tkinter.ttk.Button(root,text='选择文件',command=selectimpserfile)
impser1btn.grid(row = 0,column = 9)
down2btn = tkinter.ttk.Button(root,text='导入',command=impserver)
down2btn.grid(row = 0,column = 10)

columns = ('num','ip','port','user','pwd')
tree = tkinter.ttk.Treeview(root, height=15, show='headings', columns=columns)
tree.column('num', width=50, anchor='center')
tree.column('ip', width=120, anchor='center')
tree.column('port', width=70, anchor='center')
tree.column('user', width=88, anchor='center')
tree.column('pwd', width=88, anchor='center')
for col in columns:
    tree.heading(col, text=col.title(),
                        command=lambda c=col: treeview_sort_column(tree, c, False))

ysb = tkinter.ttk.Scrollbar(root, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=ysb.set)
for col in columns:
    tree.heading(col, text=col.title())
tree.bind("<<TreeviewSelect>>",gosel)

label1.grid(row = 0,column = 0)
ipfield.grid(row = 0,column = 1)
label2.grid(row = 1,column = 0)
portfield.grid(row = 1,column = 1)
label3.grid(row = 2,column = 0)
userfield.grid(row = 2,column = 1)
label4.grid(row = 3,column = 0)
pwdfield.grid(row = 3,column = 1)

sv = tkinter.ttk.Separator(root,orient=tkinter.VERTICAL)
sv.grid(row = 0,column = 2,rowspan=4,sticky = "ns")
sv = tkinter.ttk.Separator(root,orient=tkinter.VERTICAL)
sv.grid(row = 0,column = 3,rowspan=4,sticky = "ns")

addbtn.grid(row = 0,column = 4)
delbtn.grid(row = 1,column = 4)
flushbutn.grid(row = 2,column = 4)
msg.grid(row = 3,column = 4)

sv = tkinter.ttk.Separator(root,orient=tkinter.VERTICAL)
sv.grid(row = 0,column = 5,rowspan=19,sticky = "ns")
sv = tkinter.ttk.Separator(root,orient=tkinter.VERTICAL)
sv.grid(row = 0,column = 6,rowspan=19,sticky = "ns")

tree.grid(row = 1,column = 7,rowspan = 18,columnspan = 5)
ysb.grid(row = 1,column = 13,rowspan = 18,sticky = "ns")

sh = tkinter.ttk.Separator(root, orient=tkinter.HORIZONTAL)
sh.grid(row=4,column=0,columnspan=5,sticky="we")
sh = tkinter.ttk.Separator(root, orient=tkinter.HORIZONTAL)
sh.grid(row=5,column=0,columnspan=5,sticky="we")

msg1 = tkinter.ttk.Label(root,text = '',foreground = 'red')
msg1.grid(row = 6,column = 0,columnspan = 5)

sh = tkinter.ttk.Separator(root, orient=tkinter.HORIZONTAL)
sh.grid(row=7,column=0,columnspan=5,sticky="we")
sh = tkinter.ttk.Separator(root, orient=tkinter.HORIZONTAL)
sh.grid(row=8,column=0,columnspan=5,sticky="we")

sh = tkinter.ttk.Separator(root, orient=tkinter.HORIZONTAL)
sh.grid(row=19,column=0,columnspan=18,sticky="we")
sh = tkinter.ttk.Separator(root, orient=tkinter.HORIZONTAL)
sh.grid(row=20,column=0,columnspan=18,sticky="we")

label5.grid(row = 21,column = 0)
shellfield.grid(row = 21,column = 1,columnspan = 8)
button = tkinter.ttk.Button(root,text='运行',command=main)
button.grid(row = 21,column = 9)
button = tkinter.ttk.Button(root,text='生成服务器信息',command=checkreport)
button.grid(row = 21,column = 10)
text = ScrolledText(root,font=('Fixedsys',12),fg='blue',width=93,height=16,wrap=tkinter.WORD)
text.grid(row = 22,column = 0,rowspan = 18,columnspan = 14)

viewmsg()
root.config(menu = menubar)
root.mainloop()














