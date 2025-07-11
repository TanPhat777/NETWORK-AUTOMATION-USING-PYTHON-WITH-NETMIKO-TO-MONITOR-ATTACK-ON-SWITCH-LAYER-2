################# CODE CHÍNH ###################
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

class MACFloodMonitor:
    def __init__(self):
        self.setup_logging()

        self.log_file_path = "/var/log/syslog-remote/syslog.log"
        self.pattern = r"%PORT_SECURITY-2-PSECURE_VIOLATION:.*port (\S+)"
        self.switch_config = {
            "device_type": "cisco_ios",
            "host": "192.168.104.6",
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
        log_filename = log_dir / f"mac_flooding_monitor_{datetime.now().strftime('%Y%m%d')}.log"

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(log_filename, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )

        self.logger = logging.getLogger(__name__)
        self.logger.info("Bắt đầu theo dõi tấn công MAC Flooding")

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

    def process_mac_attack(self, interface, log_line):
        now = datetime.now()
        state = self.interface_state[interface]
        state["last_activity"] = now

        if not state["is_attacking"]:
            state["first_detected"] = now
            state["is_attacking"] = True
            state["last_log"] = log_line
            self.logger.warning(f"PHÁT HIỆN TẤN CÔNG MAC FLOODING TRÊN CỔNG {interface}")
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
                    f"{interface} - Tấn công MAC Flooding đã DỪNG (timeout). Thời gian: {duration}, "
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
            self.logger.info("Không phát hiện tấn công MAC Flooding nào.")
            return

        self.logger.info("==== BÁO CÁO TỔNG KẾT MAC FLOODING ====")
        for interface, state in self.interface_state.items():
            if state["first_detected"] or state["is_attacking"]:
                status = "Đang tấn công" nếu state["is_attacking"] else "Đã dừng"
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
                    self.process_mac_attack(interface, log_line)

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
        self.logger.info("Đã dừng MAC Flooding Monitor")

def main():
    monitor = MACFloodMonitor()
    monitor.monitor_logs()

if __name__ == "__main__":
    main()




#############################################################################
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

class MACFloodingMonitor:
    def __init__(self):
        self.setup_logging()
        self.log_file_path = "/var/log/syslog-remote/syslog.log"
        self.pattern = r"%PM-4-ERR_DISABLE.*psecure-violation.*detected on (\S+)"
        self.switch_config = {
            "device_type": "cisco_ios",
            "host": "192.168.104.6",
            "username": "admin",
            "password": "cisco123",
            "secret": "cisco123",
        }
        self.interface_state = defaultdict(lambda: {
            "counter": 0, 
            "last_log": "", 
            "first_detected": None, 
            "last_activity": None,
            "is_attacking": False,
            "mac_count": 0,
            "violation_count": 0
        })
        self.stable_threshold = 5
        self.timeout_threshold = 30
        self.alert_sound_path = "/opt/alert.mp3"
        self.running = True
        self.sound_enabled = True
        self.init_sound_system()
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def setup_logging(self):
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        log_filename = log_dir / f"mac_flooding_monitor_{datetime.now().strftime('%Y%m%d')}.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Bat dau theo doi tan cong MAC Flooding")

    def init_sound_system(self):
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
        if not self.sound_enabled:
            print("\n" + "="*50)
            print("CANH BAO: PHAT HIEN TAN CONG MAC FLOODING!")
            print("="*50 + "\n")
            return
        try:
            pygame.mixer.music.load(self.alert_sound_path)
            pygame.mixer.music.play()
            self.logger.info("Da phat am thanh canh bao")
        except Exception as e:
            self.logger.error(f"Loi phat am thanh: {e}")
            print("\n" + "="*50)
            print("CANH BAO: PHAT HIEN TAN CONG MAC FLOODING!")
            print("="*50 + "\n")

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
            self.logger.error(f"Khong tim thay file log: {self.log_file_path}")
            return
        except Exception as e:
            self.logger.error(f"Loi doc file log: {e}")
            return

    def get_mac_table_count(self, interface):
        try:
            with ConnectHandler(**self.switch_config) as connection:
                connection.enable()
                output = connection.send_command(f"show mac address-table interface {interface}")
                mac_lines = [line for line in output.split('\n') 
                             if re.match(r'^\s*\d+\s+[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}', line)]
                return len(mac_lines)
        except Exception as e:
            self.logger.error(f"Loi lay so luong MAC: {e}")
            return 0

    def process_mac_flooding_attack(self, interface, log_line):
        current_time = datetime.now()
        state = self.interface_state[interface]
        state["last_activity"] = current_time
        if not state["is_attacking"]:
            state["first_detected"] = current_time
            state["is_attacking"] = True
            state["counter"] = 0
            state["last_log"] = log_line
            state["violation_count"] = 1
            state["mac_count"] = self.get_mac_table_count(interface)
            self.logger.warning(f"PHAT HIEN TAN CONG MAC FLOODING tren cong {interface}")
            self.logger.info(f"So luong MAC hien tai: {state['mac_count']}")
            self.logger.info(f"Log: {log_line}")
            threading.Thread(target=self.play_alert, daemon=True).start()
        else:
            state["violation_count"] += 1
            if log_line == state["last_log"]:
                state["counter"] += 1
                self.logger.info(
                    f"{interface} - So lan log lap lai: {state['counter']}/{self.stable_threshold} "
                    f"(Tong violations: {state['violation_count']})"
                )
            else:
                state["counter"] = 0
                state["last_log"] = log_line
                state["mac_count"] = self.get_mac_table_count(interface)
                self.logger.info(f"Log moi: {log_line}")
                self.logger.info(f"So luong MAC cap nhat: {state['mac_count']}")
        if state["counter"] >= self.stable_threshold:
            attack_duration = current_time - state["first_detected"]
            self.logger.info(
                f"{interface} - Tan cong MAC Flooding co ve da dung (dieu kien: counter lon hon hoac bang nguong on dinh). "
                f"Thoi gian tan cong: {attack_duration}, "
                f"Tong violations: {state['violation_count']}, "
                f"So MAC cuoi cung: {state['mac_count']}"
            )
            state["is_attacking"] = False
            state["counter"] = 0
            state["first_detected"] = None

    def check_timeout_attacks(self):
        current_time = datetime.now()
        for interface, state in self.interface_state.items():
            if not state["is_attacking"] or state["last_activity"] is None:
                continue
            time_since_last_activity = current_time - state["last_activity"]
            if time_since_last_activity.total_seconds() >= self.timeout_threshold:
                attack_duration = current_time - state["first_detected"]
                self.logger.info(
                    f"{interface} - Tan cong MAC Flooding da dung do het thoi gian timeout. "
                    f"Thoi gian tan cong: {attack_duration}, "
                    f"Tong violations: {state['violation_count']}, "
                    f"Lan cuoi hoat dong: {time_since_last_activity.total_seconds():.1f}s truoc"
                )
                state["is_attacking"] = False
                state["first_detected"] = None
                state["counter"] = 0

    def generate_summary_report(self):
        active_attacks = [i for i, s in self.interface_state.items() if s["is_attacking"]]
        if not self.interface_state:
            self.logger.info("Khong phat hien tan cong MAC Flooding nao trong phien nay")
            return
        self.logger.info("BAO CAO TONG KET TAN CONG MAC FLOODING:")
        self.logger.info("=" * 50)
        for interface, state in self.interface_state.items():
            if state["first_detected"] or state["is_attacking"]:
                status = "Dang tan cong" if state["is_attacking"] else "Da dung"
                self.logger.info(
                    f"Cong: {interface}\n"
                    f"  Trang thai: {status}\n"
                    f"  Lan dau phat hien: {state['first_detected']}\n"
                    f"  Tong violations: {state['violation_count']}\n"
                    f"  So MAC cuoi cung: {state['mac_count']}"
                )
        self.logger.info("=" * 50)

    def monitor_logs(self):
        self.logger.info("Bat dau theo doi tan cong MAC Flooding...")
        self.logger.info(f"Dang theo doi file log: {self.log_file_path}")
        self.logger.info(f"Pattern: {self.pattern}")
        self.logger.info(f"Nguong on dinh: {self.stable_threshold}")
        self.logger.info(f"Nguong timeout: {self.timeout_threshold}s")
        last_timeout_check = datetime.now()
        try:
            for log_line in self.tail_log_file():
                if not self.running:
                    break
                match = re.search(self.pattern, log_line)
                if match:
                    interface = match.group(1)
                    self.process_mac_flooding_attack(interface, log_line)
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
        self.logger.info(f"Nhan signal {signum}, dang tat chuong trinh...")
        self.running = False

    def cleanup(self):
        self.logger.info("Dang don dep tai nguyen...")
        self.generate_summary_report()
        if self.sound_enabled:
            try:
                pygame.mixer.quit()
            except:
                pass
        self.logger.info("Da dung MAC Flooding Monitor")

def main():
    monitor = MACFloodingMonitor()
    monitor.monitor_logs()

if __name__ == "__main__":
    main()
