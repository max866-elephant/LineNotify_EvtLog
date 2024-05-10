import win32evtlog
import time
import requests
from datetime import datetime, timedelta


#LINE_NOTIFY_TOKEN = "Your LINE_NOTIFY_TOKEN"

logon_event_id_list = [1102, 4624, 4702, 4719, 4720, 4738, 2004, 2005, 2006, 2009]  # 登入相關的事件 ID 列表

def send_line_notification(message):
    """發送通知到 LINE"""
    url = "https://notify-api.line.me/api/notify"
    headers = {"Authorization": f"Bearer {LINE_NOTIFY_TOKEN}"}
    data = {"message": message}
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        with open('log.txt', 'a', encoding='utf-8') as log_file:
            log_file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} 發送通知失敗 {response.status_code} {response.text}\n")

def format_event_message(event):
    """格式化事件資訊為特定格式的訊息"""
    event_time = event.TimeGenerated.strftime('%Y-%m-%d %H:%M')
    message = f"時間：{event_time}\n"
    if event.EventID == 4624:  # 處理登入成功事件
        account_name = event.StringInserts[5] if len(event.StringInserts) > 5 else "Unknown"
        source_ip = event.StringInserts[18] if len(event.StringInserts) > 18 else "Unknown"
        logon_type = "遠端交互式登入" if event.StringInserts[8] == '10' else "其他類型"
        logon_id = event.StringInserts[7] if len(event.StringInserts) > 7 else 'Unknown'
        message += (f"EventID：{event.EventID}\n"
                    f"登入帳號：{account_name}\n"
                    f"來源IP：{source_ip}\n"
                    f"登入類型：{logon_type}\n"
                    f"識別碼：{logon_id}\n"
                    f"事件描述：{event.StringInserts}")
                    
    else:
        message += (f"EventID：{event.EventID}\n"
                    f"事件時間：{event_time}\n"
                    f"事件類別：{event.EventCategory}\n"
                    f"事件描述：{event.StringInserts}")
    print(f'{message}')
    return message
    
def monitor_logon_events(last_event_time):
    server = 'localhost'
    log_type = 'Security'
    handle = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    new_last_event_time = last_event_time
    try:
        with open('log.txt', 'a', encoding='utf-8') as log_file:
            log_file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} 開始讀取事件日誌...\n")
        records = win32evtlog.ReadEventLog(handle, flags, 0)
        print(f'{len(records)} records found')
        for event in reversed(records):  # 從最新到最舊處理事件
            print(f'{event.TimeGenerated} - {event.EventID}')
            if event.EventID in logon_event_id_list and event.TimeGenerated > last_event_time:
                message = format_event_message(event)
                send_line_notification(message)
                new_last_event_time = max(new_last_event_time, event.TimeGenerated)
    finally:
        win32evtlog.CloseEventLog(handle)
        
    return new_last_event_time

if __name__ == "__main__":
    last_event_time = datetime.now() - timedelta(days=1)
    while True:
        last_event_time = monitor_logon_events(last_event_time)
        time.sleep(3)
