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
        })

        self.timeout_threshold = 30
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

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler(log_file, encoding="utf-8")]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Bắt đầu theo dõi DHCP Snooping (rate-limit)")

    def init_sound_system(self):
        try:
            pygame.mixer.init()
            if not Path(self.alert_sound_path).exists():
                self.logger.warning(f"Không tìm thấy âm thanh: {self.alert_sound_path}")
                self.sound_enabled = False
            else:
                self.logger.info("Âm thanh cảnh báo đã sẵn sàng")
        except Exception as e:
            self.logger.error(f"Lỗi hệ thống âm thanh: {e}")
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

    def process_attack(self, interface, log_line):
        now = datetime.now()
        st = self.interface_state[interface]
        st["last_activity"] = now

        if not st["is_attacking"]:
            st["is_attacking"] = True
            st["first_detected"] = now

            self.logger.warning(f"PHÁT HIỆN TẤN CÔNG DHCP SNOOPING TRÊN CỔNG {interface}")
            self.logger.info(f"Log: {log_line}")
            threading.Thread(target=self.play_alert, daemon=True).start()

    def check_timeout_attacks(self):
        now = datetime.now()
        for iface, st in self.interface_state.items():
            if st["is_attacking"] and st["last_activity"]:
                delta = now - st["last_activity"]
                if delta.total_seconds() >= self.timeout_threshold:
                    dur = now - st["first_detected"]
                    self.logger.info(f"{iface} - Tấn công đã dừng (timeout). Thời gian: {dur}")
                    st.update({
                        "is_attacking": False,
                        "first_detected": None
                    })

    def generate_summary_report(self):
        self.logger.info("==== BÁO CÁO DHCP SNOOPING ====")
        for iface, st in self.interface_state.items():
            if st["first_detected"] or st["is_attacking"]:
                status = "Đang bị tấn công" if st["is_attacking"] else "Đã dừng"
                self.logger.info(f"Cổng: {iface} | Trạng thái: {status} | Lần đầu phát hiện: {st['first_detected']}")
        self.logger.info("=" * 40)

    def monitor_logs(self):
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
        self.running = False

    def cleanup(self):
        self.generate_summary_report()
        if self.sound_enabled:
            try:
                pygame.mixer.quit()
            except:
                pass
        self.logger.info("Đã dừng DHCP Snooping Monitor")

def main():
    monitor = DHCPSnoopingMonitor()
    monitor.monitor_logs()

if __name__ == "__main__":
    main()
