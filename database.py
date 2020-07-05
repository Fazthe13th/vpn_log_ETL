import mysql.connector
from datetime import datetime
import os
from dotenv import load_dotenv
from uuid import uuid1


load_dotenv()


class DataLoad:
    @classmethod
    def connect_database(cls):
        try:
            vpn_log = mysql.connector.connect(
                host=os.getenv('host'),
                user=os.getenv('user'),
                passwd=os.getenv('passwd'),
                database=os.getenv('database'),
                auth_plugin=os.getenv('auth_plugin')
            )
            return vpn_log
        except Exception as e:
            print('An error happed: ' + str(e))
            return None

    @classmethod
    def insert_user(cls, *data):
        username, last_ip, login_time = data
        vpn_log = cls.connect_database()
        if not vpn_log:
            return "Database not connected"
        cursor = vpn_log.cursor()
        try:
            insert_user_query = """INSERT INTO vpn_log.vpn_users (user_name, last_assigned_ip,last_login_time) VALUES (%s, %s, %s)"""
            val = (username, last_ip, login_time)
            cursor.execute(insert_user_query, val)
            vpn_log.commit()
            print('Added user info in users!')
        except Exception as e:
            print('User insert function Error happened: ' + str(e))
        cursor.close()
        vpn_log.close()

    @classmethod
    def update_user(cls, *data):
        username, last_ip, login_time = data
        vpn_log = cls.connect_database()
        if not vpn_log:
            return "Database not connected"
        cursor = vpn_log.cursor()
        try:
            cursor.execute("""
      UPDATE vpn_log.vpn_users
      SET last_assigned_ip=%s,last_login_time=%s
      WHERE user_name=%s
        """, (last_ip, login_time, username))
            vpn_log.commit()
            print('Updated user info in users!')
        except Exception as e:
            print('User update function Error happened: ' + str(e))

        cursor.close()
        vpn_log.close()

    def upsert_user(self, *data):
        username, last_ip, login_time = data
        vpn_log = self.connect_database()
        if not vpn_log:
            return "Database not connected"
        cursor = vpn_log.cursor()
        select_user_query = "SELECT * FROM vpn_log.vpn_users where user_name = %s"
        cursor.execute(select_user_query, (str(username),))
        selected_user = cursor.fetchone()
        if selected_user:
            self.update_user(username, last_ip, login_time)
        else:
            self.insert_user(username, last_ip, login_time)
        cursor.close()
        vpn_log.close()

    def insert_user_access_hist(self, *data):
        username, Vsync, source_ip, source_mac, logintime, logon_mode, auth_mode, device_category, parent_group = data
        vpn_log = self.connect_database()
        if not vpn_log:
            return "Database not connected"
        cursor = vpn_log.cursor()

        select_user_id = "SELECT user_id FROM vpn_log.vpn_users where user_name = %s"
        cursor.execute(select_user_id, (str(username),))
        user_id = cursor.fetchone()

        if user_id:
            try:
                insert_login_success_query = """INSERT INTO vpn_log.vpn_user_access_history 
        (access_hist_uuid,user_id,login_time,Vsync,source_ip,source_mac,logon_model,auth_mode,device_category,parent_group) 
        VALUES (%s, %s, %s,%s, %s, %s,%s, %s, %s, %s)"""
                val = (str(uuid1()), user_id[0], logintime, Vsync, source_ip,
                       source_mac, logon_mode, auth_mode, device_category, parent_group)
                cursor.execute(insert_login_success_query, val)
                vpn_log.commit()
                print('Added user info in user access history!')
            except Exception as e:
                print('Insert into access hist function Error happened: ' + str(e))

        cursor.close()
        vpn_log.close()

    def vpn_user_activity_load(self, *data):
        url_time, syslogID, Vsync, policy, src_ip, dst_ip, src_port, dst_port, src_zone, dst_zone, protocal, request_type, host, referer = data
        vpn_log = self.connect_database()
        if not vpn_log:
            return "Database not connected"
        cursor = vpn_log.cursor()

        select_user_info = "SELECT user_id, user_name FROM vpn_log.vpn_users where last_assigned_ip = %s"
        cursor.execute(select_user_info, (str(src_ip),))
        user_info = cursor.fetchone()
        if user_info:

            user_id = user_info[0]
            user_name = user_info[1]
            select_user_info = "SELECT logout_time FROM vpn_log.vpn_user_access_history where user_id = %s order by login_time desc limit 1"
            cursor.execute(select_user_info, (int(user_id),))
            logout_time = cursor.fetchone()

            if not logout_time[0]:

                try:
                    insert_user_activity_query = """INSERT INTO vpn_log.vpn_user_activity 
          (activity_uuid,user_id,username,syslogID,Vsync,policy,src_ip,dst_ip,src_port,dst_port,src_zone,dst_zone,protocal,request_type,host,referer,url_access_time) 
          VALUES (%s, %s, %s,%s, %s, %s,%s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s)"""
                    val = (str(uuid1()), user_id, user_name, syslogID, Vsync, policy, src_ip, dst_ip,
                           src_port, dst_port, src_zone, dst_zone, protocal, request_type, host, referer, url_time)
                    cursor.execute(insert_user_activity_query, val)
                    vpn_log.commit()
                    print('Added user activity info!')
                except Exception as e:
                    print('User activity load function Error happened: ' + str(e))
            else:
                print('User not logged in')

        cursor.close()
        vpn_log.close()

    def vpn_user_login_fail(self, *data):
        device_mac, device_name, username, MAC, ip_address, time, zone, access_type = data
        time = int(time)
        vpn_log = self.connect_database()
        if not vpn_log:
            return "Database not connected"
        cursor = vpn_log.cursor()
        try:
            insert_login_fail_query = """INSERT INTO vpn_log.vpn_login_fail_hist 
      (failed_uuid,device_mac,device_name,username,MAC,ip_address,zone,access_type,time) 
      VALUES (%s, %s, %s,%s, %s, %s,%s, %s, %s)"""
            val = (str(uuid1()), device_mac, device_name, username, MAC, ip_address, zone,
                   access_type, datetime.utcfromtimestamp(time).strftime('%Y-%m-%d %H:%M:%S'))
            cursor.execute(insert_login_fail_query, val)
            vpn_log.commit()
            print('Added user login fail info!')
        except Exception as e:
            print('Login fail function Error happened: ' + str(e))
        cursor.close()
        vpn_log.close()

    def user_logout(self, *data):
        username, logouttime = data
        vpn_log = self.connect_database()
        if not vpn_log:
            return "Database not connected"
        cursor = vpn_log.cursor()
        select_user_id = "SELECT user_id FROM vpn_log.vpn_users where user_name = %s"
        cursor.execute(select_user_id, (str(username),))
        user_id = cursor.fetchone()
        if user_id:
            last_login_query = "SELECT access_hist_uuid FROM vpn_log.vpn_user_access_history where user_id = %s order by login_time desc limit 1"
            cursor.execute(last_login_query, (int(user_id[0]),))
            last_login_uuid = cursor.fetchone()
        else:
            return 'Previous login info not found'

        if user_id:
            try:
                cursor.execute("""
        UPDATE vpn_log.vpn_users
        SET last_logout_time=%s
        WHERE user_name=%s
          """, (logouttime, username))
                vpn_log.commit()
                print('Updated user logout info in users!')
            except Exception as e:
                print('Logout function - user tree Error happened: ' + str(e))
        if last_login_uuid:
            try:
                cursor.execute("""
        UPDATE vpn_log.vpn_user_access_history
        SET logout_time=%s
        WHERE access_hist_uuid=%s
          """, (logouttime, last_login_uuid[0]))
                vpn_log.commit()
                print('Updated user logout info in access history!')
            except Exception as e:
                print('Logout function - access history tree Error happened: ' + str(e))
        cursor.close()
        vpn_log.close()
