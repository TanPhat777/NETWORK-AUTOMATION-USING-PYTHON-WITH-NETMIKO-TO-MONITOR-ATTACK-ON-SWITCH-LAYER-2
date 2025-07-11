import time
import re
from datetime import datetime
from netmiko import ConnectHandler
import pygame
import threading

log_file_path = "/var/log/syslog-remote/syslog.log"
pattern = r"%SPANTREE-2-BLOCK_BPDUGUARD.*port (\S+)"

switch = {
    "device_type": "cisco_ios",
    "host": "192.168.104.7",
    "username": "admin",
    "password": "cisco123",
    "secret": "cisco123",
}

interface_state = {}
poll_interval = 5
stable_threshold = 5

# Hàm phát âm thanh
def play_alert():
    pygame.mixer.init()
    pygame.mixer.music.load("/opt/alert.mp3")  # Đảm bảo file alert.mp3 nằm ở /opt/
    pygame.mixer.music.play()

def tail_log():
    with open(log_file_path, "r") as f:
        f.seek(0, 2)
        while True:
            dong = f.readline()
            if not dong:
                time.sleep(0.1)
                continue
            yield dong.strip()

def monitor_log():
    for dong_log in tail_log():
        match = re.search(pattern, dong_log)
        if match:
            interface = match.group(1)
            print(f"[{datetime.now()}] Phat hien tan cong BPDU tren {interface}: {dong_log}")
            
            # Phát âm thanh cảnh báo
            threading.Thread(target=play_alert, daemon=True).start()

            if interface not in interface_state:
                interface_state[interface] = {
                    "counter": 0,
                    "last_log": dong_log
                }
            else:
                if dong_log == interface_state[interface]["last_log"]:
                    interface_state[interface]["counter"] += 1
                    print(f"[{datetime.now()}] {interface} log khong thay doi ({interface_state[interface]['counter']}/{stable_threshold})")
                else:
                    interface_state[interface]["counter"] = 0
                    interface_state[interface]["last_log"] = dong_log
                    print(f"[{datetime.now()}] {interface} phat hien log moi -> dang con bi tan cong")

            if interface_state[interface]["counter"] >= stable_threshold:
                print(f"[{datetime.now()}] {interface} da on dinh -> co the hacker da ngung tan cong")
                interface_state[interface]["counter"] = 0

if __name__ == "__main__":
    monitor_log()



##################
import time
import re
import logging
from datetime import datetime
from pathlib import Path
from netmiko import ConnectHandler
import pygame
import threading
from collections import defaultdict
import signal
import sys

class BPDUMonitor:
    def __init__(self):
        self.setup_logging()

        self.log_file_path = "/var/log/syslog-remote/syslog.log"
        self.pattern = r"%SPANTREE-2-BLOCK_BPDUGUARD.*port (\S+)"
        self.switch_config = {
            "device_type": "cisco_ios",
            "host": "192.168.104.7",
            "username": "admin",
            "password": "cisco123",
            "secret": "cisco123",
        }

        self.interface_state = defaultdict(lambda: {
            "last_log": "",
            "first_detected": None,
            "last_activity": None,
            "is_attacking": False
        })
        self.timeout_threshold = 30  # giây
        self.alert_sound_path = "/opt/alert.mp3"
        self.running = True
        self.sound_enabled = True

        self.init_sound_system()

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def setup_logging(self):
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        log_filename = log_dir / f"bpdu_monitor_{datetime.now().strftime('%Y%m%d')}.log"

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(log_filename, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )

        self.logger = logging.getLogger(__name__)
        self.logger.info("Bắt đầu theo dõi tấn công BPDU")

    def init_sound_system(self):
        try:
            pygame.mixer.init()
            if not Path(self.alert_sound_path).exists():
                self.logger.warning(f"Không tìm thấy file âm thanh: {self.alert_sound_path}")
                self.sound_enabled = False
            else:
                self.logger.info("Hệ thống âm thanh đã sẵn sàng")
        except Exception as e:
            self.logger.error(f"Lỗi khởi tạo âm thanh: {e}")
            self.sound_enabled = False

    def play_alert(self):
        if not self.sound_enabled:
            return
        try:
            pygame.mixer.music.load(self.alert_sound_path)
            pygame.mixer.music.play()
        except Exception as e:
            self.logger.error(f"Lỗi phát âm thanh: {e}")

    def tail_log_file(self):
        try:
            with open(self.log_file_path, "r", encoding='utf-8') as f:
                f.seek(0, 2)
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    yield line.strip()
        except FileNotFoundError:
            self.logger.error(f"Không tìm thấy file log: {self.log_file_path}")
        except Exception as e:
            self.logger.error(f"Lỗi đọc file log: {e}")

    def process_bpdu_attack(self, interface, log_line):
        now = datetime.now()
        state = self.interface_state[interface]
        state["last_activity"] = now

        if not state["is_attacking"]:
            state["first_detected"] = now
            state["is_attacking"] = True
            state["last_log"] = log_line
            self.logger.warning(f"PHÁT HIỆN TẤN CÔNG BPDU TRÊN CỔNG {interface}")
            self.logger.info(f"Log: {log_line}")
            threading.Thread(target=self.play_alert, daemon=True).start()
        else:
            if log_line != state["last_log"]:
                state["last_log"] = log_line
                self.logger.info(f"Log: {log_line}")

    def check_timeout_attacks(self):
        now = datetime.now()
        for interface, state in self.interface_state.items():
            if not state["is_attacking"] or not state["last_activity"]:
                continue
            delta = now - state["last_activity"]
            if delta.total_seconds() >= self.timeout_threshold:
                duration = now - state["first_detected"]
                self.logger.info(
                    f"{interface} - Tấn công đã DỪNG (timeout). Thời gian: {duration}, "
                    f"Lần cuối hoạt động: {delta.total_seconds():.1f}s trước"
                )
                state.update({
                    "is_attacking": False,
                    "first_detected": None,
                    "last_log": "",
                    "last_activity": None
                })

    def generate_summary_report(self):
        if not self.interface_state:
            self.logger.info("Không phát hiện tấn công BPDU nào.")
            return

        self.logger.info("==== BÁO CÁO TỔNG KẾT BPDU ====")
        for interface, state in self.interface_state.items():
            if state["first_detected"] or state["is_attacking"]:
                status = "Đang tấn công" if state["is_attacking"] else "Đã dừng"
                self.logger.info(
                    f"Cổng: {interface}\n"
                    f"  Trạng thái: {status}\n"
                    f"  Lần đầu phát hiện: {state['first_detected']}"
                )
        self.logger.info("=" * 50)

    def monitor_logs(self):
        self.logger.info(f"Đang theo dõi file log: {self.log_file_path}")
        self.logger.info(f"Ngưỡng timeout: {self.timeout_threshold}s")

        last_timeout_check = datetime.now()

        try:
            for log_line in self.tail_log_file():
                if not self.running:
                    break
                match = re.search(self.pattern, log_line)
                if match:
                    interface = match.group(1)
                    self.process_bpdu_attack(interface, log_line)

                now = datetime.now()
                if (now - last_timeout_check).total_seconds() >= 10:
                    self.check_timeout_attacks()
                    last_timeout_check = now
        except Exception as e:
            self.logger.error(f"Lỗi theo dõi: {e}")
        finally:
            self.cleanup()

    def signal_handler(self, signum, frame):
        self.logger.info(f"Nhận tín hiệu {signum}, đang tắt chương trình...")
        self.running = False

    def cleanup(self):
        self.logger.info("Đang dọn dẹp tài nguyên...")
        self.generate_summary_report()
        if self.sound_enabled:
            try:
                pygame.mixer.quit()
            except:
                pass
        self.logger.info("Đã dừng BPDU Monitor")

def main():
    monitor = BPDUMonitor()
    monitor.monitor_logs()

if __name__ == "__main__":
    main()




################################# Code Claud.ai ####################################33
import time
import re
import logging
from datetime import datetime
from pathlib import Path
from netmiko import ConnectHandler
import pygame
import threading
from collections import defaultdict
import signal
import sys

class BPDUMonitor:
    def __init__(self):
        # Cấu hình logging
        self.setup_logging()

        # Cau hinh mac dinh
        self.log_file_path = "/var/log/syslog-remote/syslog.log"
        self.pattern = r"%SPANTREE-2-BLOCK_BPDUGUARD.*port (\S+)"
        self.switch_config = {
            "device_type": "cisco_ios",
            "host": "192.168.104.7",
            "username": "admin",
            "password": "cisco123",
            "secret": "cisco123",
        }
        
        # Cau hinh monitor
        self.interface_state = defaultdict(lambda: {
            "counter": 0, 
            "last_log": "", 
            "first_detected": None, 
            "last_activity": None,
            "is_attacking": False
        })
        self.stable_threshold = 5
        self.timeout_threshold = 30  # 30 giay khong co log moi = dung tan cong
        self.alert_sound_path = "/opt/alert.mp3"

        # Flags dieu khien
        self.running = True
        self.sound_enabled = True

        # Khoi tao pygame mixer
        self.init_sound_system()

        # Thiet lap signal handler de dung gracefully
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def setup_logging(self):
        """Thiet lap logging system"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        log_filename = log_dir / f"bpdu_monitor_{datetime.now().strftime('%Y%m%d')}.log"

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )

        self.logger = logging.getLogger(__name__)
        self.logger.info("Bat dau theo doi tan cong BPDU")
    
    def init_sound_system(self):
        """Khoi tao he thong am thanh"""
        try:
            pygame.mixer.init()
            if not Path(self.alert_sound_path).exists():
                self.logger.warning(f"Khong tim thay file am thanh: {self.alert_sound_path}")
                self.sound_enabled = False
            else:
                self.logger.info("He thong am thanh da san sang")
        except Exception as e:
            self.logger.error(f"Loi khoi tao am thanh: {e}")
            self.sound_enabled = False
               
    def play_alert(self):
        """Phat am thanh canh bao"""
        if not self.sound_enabled:
            return

        try:
            pygame.mixer.music.load(self.alert_sound_path)
            pygame.mixer.music.play()
        except Exception as e:
            self.logger.error(f"Loi phat am thanh: {e}")
    
    def tail_log_file(self):
        """Doc log file theo thoi gian thuc"""
        try:
            with open(self.log_file_path, "r", encoding='utf-8') as f:
                # Di chuyen den cuoi file
                f.seek(0, 2)

                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    yield line.strip()

        except FileNotFoundError:
            self.logger.error(f"Khong tim thay file log: {self.log_file_path}")
            return
        except Exception as e:
            self.logger.error(f"Loi doc file log: {e}")
            return
    
    def process_bpdu_attack(self, interface, log_line):
        """Xu ly khi phat hien tan cong BPDU"""
        current_time = datetime.now()
        state = self.interface_state[interface]

        # Cap nhat thoi gian hoat dong cuoi cung
        state["last_activity"] = current_time

        # Lan dau phat hien tan cong tren interface nay
        if not state["is_attacking"]:
            state["first_detected"] = current_time
            state["is_attacking"] = True
            state["counter"] = 0
            state["last_log"] = log_line

            self.logger.warning(f"PHAT HIEN TAN CONG BPDU tren cong {interface}")
            self.logger.info(f"Log: {log_line}")

            # Phat am thanh canh bao
            threading.Thread(target=self.play_alert, daemon=True).start()

        else:
            # Dang trong trang thai bi tan cong
            if log_line == state["last_log"]:
                state["counter"] += 1
                self.logger.info(
                    f"{interface} - So lan log lap lai: {state['counter']}/{self.stable_threshold}"
                )
            else:
                # Log moi xuat hien -> van dang bi tan cong
                state["counter"] = 0
                state["last_log"] = log_line
                self.logger.info(f"Log: {log_line}")

        # Kiem tra xem co on dinh khong (co the da dung)
        if state["counter"] >= self.stable_threshold:
            attack_duration = current_time - state["first_detected"]
            self.logger.info(
                f"{interface} - Tan cong co ve da dung. "
                f"Thoi gian tan cong: {attack_duration}"
            )
            
            # Danh dau da dung tan cong
            state["is_attacking"] = False
            state["counter"] = 0
            state["first_detected"] = None
    
    def check_timeout_attacks(self):
        """Kiem tra cac interface co the da dung tan cong do timeout"""
        current_time = datetime.now()
        
        for interface, state in self.interface_state.items():
            if not state["is_attacking"] or state["last_activity"] is None:
                continue

            # Tinh thoi gian khong co hoat dong
            time_since_last_activity = current_time - state["last_activity"]

            # Neu khong co log moi trong timeout_threshold giay
            if time_since_last_activity.total_seconds() >= self.timeout_threshold:
                attack_duration = current_time - state["first_detected"]
                self.logger.info(
                    f"{interface} - Tan cong da dung (phat hien timeout). "
                    f"Thoi gian tan cong: {attack_duration}, "
                    f"Lan cuoi hoat dong: {time_since_last_activity.total_seconds():.1f}s truoc"
                )
                
                # Danh dau da dung tan cong
                state["is_attacking"] = False
                state["first_detected"] = None
                state["counter"] = 0
    
    def get_interface_status(self, interface):
        """Lay trang thai interface tu switch"""
        try:
            with ConnectHandler(**self.switch_config) as connection:
                connection.enable()
                output = connection.send_command(f"show interface {interface} status")
                return output
        except Exception as e:
            self.logger.error(f"Loi lay trang thai interface: {e}")
            return None
    
    def generate_summary_report(self):
        """Tao bao cao tong ket"""
        active_attacks = [interface for interface, state in self.interface_state.items() 
                         if state["is_attacking"]]
        
        if not self.interface_state:
            self.logger.info("Khong phat hien tan cong BPDU nao trong phien nay")
            return
            
        self.logger.info("BAO CAO TONG KET TAN CONG BPDU:")
        self.logger.info("=" * 50)

        for interface, state in self.interface_state.items():
            if state["first_detected"] or state["is_attacking"]:
                status = "Dang tan cong" if state["is_attacking"] else "Da dung"
                self.logger.info(
                    f"Cong: {interface}\n"
                    f"  Trang thai: {status}\n"
                    f"  Lan dau phat hien: {state['first_detected']}"
                )

        self.logger.info("=" * 50)
    
    def monitor_logs(self):
        """Ham chinh de monitor logs"""
        self.logger.info("Bat dau theo doi tan cong BPDU...")
        self.logger.info(f"Dang theo doi file log: {self.log_file_path}")
        self.logger.info(f"Nguong on dinh: {self.stable_threshold}")
        self.logger.info(f"Nguong timeout: {self.timeout_threshold}s")

        last_timeout_check = datetime.now()

        try:
            for log_line in self.tail_log_file():
                if not self.running:
                    break

                # Tim kiem pattern BPDU attack
                match = re.search(self.pattern, log_line)
                if match:
                    interface = match.group(1)
                    self.process_bpdu_attack(interface, log_line)

                # Kiem tra timeout moi 10 giay
                current_time = datetime.now()
                if (current_time - last_timeout_check).total_seconds() >= 10:
                    self.check_timeout_attacks()
                    last_timeout_check = current_time

        except KeyboardInterrupt:
            self.logger.info("Da dung theo doi theo yeu cau nguoi dung")
        except Exception as e:
            self.logger.error(f"Loi trong qua trinh theo doi: {e}")
        finally:
            self.cleanup()
    
    def signal_handler(self, signum, frame):
        """Xu ly signal de dung chuong trinh gracefully"""
        self.logger.info(f"Nhan signal {signum}, dang tat chuong trinh...")
        self.running = False
    
    def cleanup(self):
        """Don dep tai nguyen"""
        self.logger.info("Dang don dep tai nguyen...")

        # Tao bao cao tong ket
        self.generate_summary_report()

        # Dung pygame mixer
        if self.sound_enabled:
            try:
                pygame.mixer.quit()
            except:
                pass

        self.logger.info("Da dung BPDU Monitor")

def main():
    """Ham main"""
    monitor = BPDUMonitor()
    monitor.monitor_logs()

if __name__ == "__main__":
    main()































