import pandas as pd
from datetime import datetime
import re
from database import DataLoad
import os
from dotenv import load_dotenv


load_dotenv()

dataload = DataLoad()

class ParseLog:
    dataload = DataLoad()
    def read_log(self):
        file = os.getenv('file_name')
        chunksize = 100000
        j = 0
        # total_line_processed = 0
        # total_line_ignored = 0
        for df in pd.read_csv(file, sep='\t', header=None, error_bad_lines=False, engine='python', chunksize=chunksize,
                              iterator=True):
            j = j + 1
            self.process_chunk(df)
    @classmethod
    def process_chunk(cls, chunk_df):
        "process chunks "
        # chunk_line_processed = 0
        # chunk_line_ignored = 0
        for index, row in chunk_df.iterrows():
            cls.read_lines(row[0])
    @classmethod
    def read_lines(cls, line):
        
        if line.find('User login succeeded') != -1:
            cls.user_login_parse(line)
        if line.find('The user logged out') != -1:
            cls.user_logout_parse(line)
        if line.find('The URL filtering policy was matched') != -1:
            cls.url_filter_parse(line)
        if line.find('RESULT:Authentication fail') != -1:
            cls.login_fail_parse(line)
    @classmethod   
    def user_login_parse(cls, line):
        "Use Regex to read the lines"
        user_loin_info_pattern = r"(?=User Name).*(?<!(\)))"
        user_login_ifo = re.search(user_loin_info_pattern, line, flags=0).group().strip()
        user_login_ifo_array = [x.strip('"') for x in user_login_ifo.split(',')]
        username = user_login_ifo_array[0].split('=')
        Vsync = user_login_ifo_array[1].split('=')
        source_ip = user_login_ifo_array[2].split('=')
        source_mac = user_login_ifo_array[3].split('=')
        login_time = user_login_ifo_array[4].split('=')
        logon_mode = user_login_ifo_array[5].split('=')
        auth_mode = user_login_ifo_array[6].split('=')
        device_category = user_login_ifo_array[7].split('=')
        parent_group = user_login_ifo_array[8].split('=')
        logintime_raw = str(login_time[1].strip())
        logintime = datetime.strptime(logintime_raw, '%Y/%m/%d %H:%M:%S')
        # print(username,Vsync,source_mac,source_ip,logintime,logon_mode,auth_mode,device_category,parent_group,)
        "Data sent to database for query"
        dataload.upsert_user(
            username[1],
            source_ip[1],
            logintime
        )
        dataload.insert_user_access_hist(
            username[1],
            Vsync[1],
            source_ip[1],
            source_mac[1],
            logintime,
            logon_mode[1],
            auth_mode[1],
            device_category[1],
            parent_group[1]
            )
    @classmethod
    def login_fail_parse(self, line):
        "Use Regex to read the lines"
        user_login_fail_pattern = r"(?=DEVICEMAC).*(?<!(\;))"
        user_login_fail_info = re.search(user_login_fail_pattern, line, flags=0).group().strip()
        user_login_fail_info_array = [x.strip('"') for x in user_login_fail_info.split(';')]
        device_mac = user_login_fail_info_array[0].split(':')
        device_name = user_login_fail_info_array[1].split(':')
        username = user_login_fail_info_array[2].split(':')
        MAC = user_login_fail_info_array[3].split(':')
        ip_address = user_login_fail_info_array[4].split(':')
        time = user_login_fail_info_array[5].split(':')
        zone = user_login_fail_info_array[6].split(':')
        access_type = user_login_fail_info_array[11].split(':')
        # print(device_mac,device_name,username,MAC,ip_address,time,zone,access_type)
        dataload.vpn_user_login_fail(
            device_mac[1],
            device_name[1],
            username[1],
            MAC[1],
            ip_address[1],
            time[1],
            zone[1],
            access_type[1]
        )
    
    @classmethod
    def user_logout_parse(cls, line):
        "Use Regex to read the lines"
        user_logout_pattern = r"(?=User Name).*(?<!(\)))"
        user_logout_ifo = re.search(user_logout_pattern, line, flags=0).group().strip()
        user_logout_ifo_array = [x.strip('"') for x in user_logout_ifo.split(',')]
        username = user_logout_ifo_array[0].split('=')
        # Vsync = user_logout_ifo_array[1].split('=')
        # source_ip = user_logout_ifo_array[2].split('=')
        # parent_group = user_logout_ifo_array[3].split('=')
        # login_time = user_logout_ifo_array[4].split('=')
        logout_time = user_logout_ifo_array[5].split('=')
        logouttime_raw = str(logout_time[1].strip())
        logouttime = datetime.strptime(logouttime_raw, '%Y/%m/%d %H:%M:%S')
        # print(username,logouttime)
        "Data sent to database for query"
        dataload.user_logout(username[1], logouttime)
    @classmethod
    def url_filter_parse(cls, line):
        "Use Regex to read the lines"
        url_info_pattern = r"(?=SyslogId).*(?<!(\)))"
        "Fix time"
        monthday_pattern = r"^[JFMASOND][aepuco][nbrylgptvc].\d+[ ]"
        time_pattern = r"\d+[:]\d+[:]\d+"
        month_day = re.search(monthday_pattern, line, flags=0)
        time = re.search(time_pattern, line, flags=0)
        month_day_split = month_day.group().strip().split()
        month = str(month_day_split[0].strip())
        day = str(month_day_split[1].strip())
        time = str(time.group().strip())
        if month == 'Dec' and day == '31':
            year = str(int(datetime.today().year) - 1)
        else:
            year = str(datetime.today().year)
        url_time = datetime.strptime(month+ ' '+ day+' '+ year+' '+ time, '%b %d %Y %H:%M:%S')
        "Fix time end"
        url_info = re.search(url_info_pattern, line, flags=0).group().strip()
        url_info_array = [x.strip('"') for x in url_info.split(',')]
        syslogID = url_info_array[0].split('=')
        Vsync = url_info_array[1].split('=')
        policy = url_info_array[2].split('=')
        src_ip = url_info_array[3].split('=')
        dst_ip = url_info_array[4].split('=')
        src_port = url_info_array[5].split('=')
        dst_port = url_info_array[6].split('=')
        src_zone = url_info_array[7].split('=')
        dst_zone = url_info_array[8].split('=')
        # username = url_info_array[#need to query with from database user table 9
        protocal= url_info_array[10].split('=')
        request_type = url_info_array[11].split('=')
        host = url_info_array[18].split('=')
        referer = url_info_array[19].split('=')
        # print(url_time,syslogID,Vsync,policy,src_ip,src_port,src_zone,dst_ip,dst_port,dst_zone,protocal,request_type,host,referer)
        "Data sent to database for query"
        dataload.vpn_user_activity_load(
            url_time,
            syslogID[1].strip('"'),
            Vsync[1].strip('"'),
            policy[1].strip('"'),
            src_ip[1].strip('"'),
            dst_ip[1].strip('"'),
            src_port[1].strip('"'),
            dst_port[1].strip('"'),
            src_zone[1].strip('"'),
            dst_zone[1].strip('"'),
            protocal[1].strip('"'),
            request_type[1].strip('"'),
            host[1].strip('"'),
            referer[1].strip('"')
            )
        
