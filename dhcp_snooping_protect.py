# -*- coding: utf-8 -*-
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
import os

class DHCPSnoopingMonitor:
    def __init__(self):
        self.setup_logging()

        self.log_file_path = "/var/log/syslog-remote/syslog.log"

        # Mẫu log cảnh báo DHCP snooping rate-limit
        self.pattern = r"%DHCP_SNOOPING-\d+-DHCP_SNOOPING_ERRDISABLE_WARNING:.*interface (\S+)"

        self.switch_config = {
            "device_type": "cisco_ios",
            "host": "192.168.104.7",  # IP mới
            "username": "admin",
            "password": "cisco123",
            "secret": "cisco123",
        }

        self.alert_sound_path = "/opt/alert.mp3"
        self.interface_state = defaultdict(lambda: {
            "is_attacking": False,
            "first_detected": None,
            "last_activity": None,
            "attack_count": 0,
            "attack_timestamps": [],
            "is_persistent": False,
            "recovery_cycle": False
        })

        self.timeout_threshold = 30
        self.recovery_interval = 30  # Thời gian recovery của switch
        self.persistent_threshold = 3  # Số lần tấn công để coi là persistent
        self.running = True
        self.sound_enabled = True

        self.init_sound_system()
        signal.signal(signal.SIGINT,  self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def setup_logging(self):
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        fn = f"dhcp_snooping_monitor_{datetime.now().strftime('%Y%m%d')}.log"
        log_file = log_dir / fn

        # Chỉ ghi log vào file, không in ra terminal
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler(log_file, encoding="utf-8")]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Bắt đầu theo dõi DHCP Snooping (rate-limit)")

    def init_sound_system(self):
        try:
            # Ẩn pygame welcome message
            os.environ['PYGAME_HIDE_SUPPORT_PROMPT'] = '1'
            
            # Khởi tạo pygame mixer với các tham số cụ thể
            pygame.mixer.pre_init(frequency=22050, size=-16, channels=2, buffer=512)
            pygame.mixer.init()
            
            if not Path(self.alert_sound_path).exists():
                self.logger.warning(f"Không tìm thấy âm thanh: {self.alert_sound_path}")
                self.sound_enabled = False
            else:
                self.logger.info("Âm thanh cảnh báo đã sẵn sàng")
        except Exception as e:
            self.logger.warning(f"Không thể khởi tạo âm thanh: {e}. Chạy ở chế độ im lặng.")
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
            with open(self.log_file_path, "r", encoding="utf-8") as f:
                f.seek(0, 2)
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    yield line.strip()
        except Exception as e:
            self.logger.error(f"Lỗi đọc log: {e}")

    def is_recovery_cycle_attack(self, interface):
        """Kiểm tra xem có phải là tấn công liên tục qua recovery cycle không"""
        st = self.interface_state[interface]
        timestamps = st["attack_timestamps"]
        
        if len(timestamps) < 2:
            return False
            
        # Kiểm tra khoảng cách giữa các lần tấn công
        recent_timestamps = [ts for ts in timestamps if (datetime.now() - ts).total_seconds() <= 120]
        
        if len(recent_timestamps) >= self.persistent_threshold:
            # Kiểm tra pattern ~30s giữa các lần tấn công
            intervals = []
            for i in range(1, len(recent_timestamps)):
                interval = (recent_timestamps[i] - recent_timestamps[i-1]).total_seconds()
                intervals.append(interval)
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                # Nếu khoảng cách trung bình gần với recovery interval (±10s)
                if 20 <= avg_interval <= 40:
                    return True
                    
        return False

    def process_attack(self, interface, log_line):
        now = datetime.now()
        st = self.interface_state[interface]
        st["last_activity"] = now
        st["attack_count"] += 1
        st["attack_timestamps"].append(now)
        
        # Giữ lại chỉ 10 timestamps gần nhất
        if len(st["attack_timestamps"]) > 10:
            st["attack_timestamps"] = st["attack_timestamps"][-10:]

        # Kiểm tra tấn công liên tục
        is_recovery_cycle = self.is_recovery_cycle_attack(interface)
        
        if not st["is_attacking"]:
            st["is_attacking"] = True
            st["first_detected"] = now
            st["recovery_cycle"] = is_recovery_cycle

            # Ghi log đầy đủ vào file
            self.logger.warning(f"PHÁT HIỆN TẤN CÔNG DHCP SNOOPING TRÊN CỔNG {interface}")
            self.logger.info(f"Log: {log_line}")
            
            if is_recovery_cycle:
                st["is_persistent"] = True
                self.logger.warning(f"TẤN CÔNG LIÊN TỤC được phát hiện trên {interface} (Recovery cycle)")
                print(f"[{now.strftime('%H:%M:%S')}] [CANH BAO CAO] TAN CONG LIEN TUC - Cong: {interface} (Lan thu {st['attack_count']})")
                print(f"[{now.strftime('%H:%M:%S')}] [THONG TIN] Cong bi err-disable, se tu dong recovery sau 30 giay")
                print(f"[{now.strftime('%H:%M:%S')}] [CANH BAO] Day la tan cong lien tuc qua recovery cycle!")
            else:
                # Chỉ hiển thị thông tin cơ bản trên terminal
                print(f"[{now.strftime('%H:%M:%S')}] [CANH BAO] PHAT HIEN TAN CONG - Cong: {interface} (Lan thu {st['attack_count']})")
            
            threading.Thread(target=self.play_alert, daemon=True).start()
        else:
            # Tấn công đang tiếp tục
            if is_recovery_cycle and not st["is_persistent"]:
                st["is_persistent"] = True
                self.logger.warning(f"Tấn công trên {interface} chuyển thành LIÊN TỤC")
                print(f"[{now.strftime('%H:%M:%S')}] [CANH BAO CAO] TAN CONG CHUYEN THANH LIEN TUC - Cong: {interface}")
                print(f"[{now.strftime('%H:%M:%S')}] [THONG TIN] Cong se duoc khoi phuc tu dong sau 30 giay")
            elif st["is_persistent"]:
                print(f"[{now.strftime('%H:%M:%S')}] [CANH BAO CAO] TAN CONG LIEN TUC TIEP TUC - Cong: {interface} (Lan thu {st['attack_count']})")
                print(f"[{now.strftime('%H:%M:%S')}] [THONG TIN] Cong bi err-disable, dang cho recovery cycle...")

    def check_timeout_attacks(self):
        now = datetime.now()
        for iface, st in self.interface_state.items():
            if st["is_attacking"] and st["last_activity"]:
                delta = now - st["last_activity"]
                if delta.total_seconds() >= self.timeout_threshold:
                    dur = now - st["first_detected"]
                    
                    if st["is_persistent"]:
                        # Ghi log vào file
                        self.logger.info(f"{iface} - Tấn công liên tục tạm dừng (timeout). Thời gian: {dur}")
                        
                        # Hiển thị trên terminal
                        print(f"[{now.strftime('%H:%M:%S')}] [THONG TIN] Tan cong lien tuc tam dung - Cong: {iface}")
                        print(f"[{now.strftime('%H:%M:%S')}] [CANH BAO] Se tiep tuc khi cong duoc recovery tu dong!")
                    else:
                        # Ghi log vào file
                        self.logger.info(f"{iface} - Tấn công đã dừng (timeout). Thời gian: {dur}")
                        
                        # Hiển thị trên terminal
                        print(f"[{now.strftime('%H:%M:%S')}] [THONG TIN] Tan cong da dung - Cong: {iface}")
                    
                    st.update({
                        "is_attacking": False,
                        "first_detected": None
                    })
                    # Không reset is_persistent để theo dõi pattern

    def generate_summary_report(self):
        self.logger.info("==== BÁO CÁO DHCP SNOOPING ====")
        for iface, st in self.interface_state.items():
            if st["first_detected"] or st["is_attacking"] or st["attack_count"] > 0:
                status = "Đang bị tấn công" if st["is_attacking"] else "Đã dừng"
                attack_type = "Liên tục" if st["is_persistent"] else "Đơn lẻ"
                self.logger.info(f"Cổng: {iface} | Trạng thái: {status} | Loại: {attack_type} | Số lần: {st['attack_count']} | Lần đầu: {st['first_detected']}")
        self.logger.info("=" * 40)

    def monitor_logs(self):
        # Hiển thị trạng thái khởi động trên terminal
        print(f"[KHOI DONG] Dang theo doi DHCP Snooping - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[LOG FILE] {self.log_file_path}")
        print(f"[AM THANH] {'Bat' if self.sound_enabled else 'Tat'}")
        print(f"[RECOVERY] Chu ky khoi phuc tu dong: {self.recovery_interval} giay")
        print("=" * 50)
        
        last_check = datetime.now()
        for line in self.tail_log_file():
            if not self.running:
                break
            m = re.search(self.pattern, line)
            if m:
                iface = m.group(1)
                self.process_attack(iface, line)

            if (datetime.now() - last_check).total_seconds() >= 10:
                self.check_timeout_attacks()
                last_check = datetime.now()

        self.cleanup()

    def signal_handler(self, sig, frame):
        self.logger.info(f"Nhận tín hiệu {sig}, dừng chương trình...")
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] [DUNG] Dung chuong trinh...")
        self.running = False

    def cleanup(self):
        self.generate_summary_report()
        if self.sound_enabled:
            try:
                pygame.mixer.quit()
            except:
                pass
        self.logger.info("Đã dừng DHCP Snooping Monitor")
        print("[HOAN THANH] Da dung DHCP Snooping Monitor")

def main():
    monitor = DHCPSnoopingMonitor()
    monitor.monitor_logs()

if __name__ == "__main__":
    main()
