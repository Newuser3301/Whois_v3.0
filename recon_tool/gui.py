import json
from datetime import datetime

import dns.exception
import dns.resolver
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtWidgets import *

from .utils import normalize_domain
from .workers import DNSLookupWorker, ReconWorker

class PentestWhoisGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.setup_style()
        
    def init_ui(self):
        """Asosiy interfeysni yaratish"""
        self.setWindowTitle("🎯 PENTEST RECON v3.1 - WHOIS & DNS Analyzer")
        self.setGeometry(100, 100, 1300, 800)
        
        # Markaziy widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Asosiy layout
        main_layout = QVBoxLayout(central_widget)
        
        # ============ HEADER ============
        header = QLabel("🔍 RED TEAM RECONNAISSANCE TOOL")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            padding: 15px;
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                                      stop:0 #ff0000, stop:1 #000000);
            color: white;
            border-radius: 8px;
        """)
        main_layout.addWidget(header)
        
        # ============ INPUT SECTION ============
        input_layout = QHBoxLayout()
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("🔗 Domen kiriting (masalan: asilmedia.org)")
        self.domain_input.setMinimumHeight(40)
        self.domain_input.returnPressed.connect(self.start_recon)
        
        self.scan_btn = QPushButton("🚀 RECON START")
        self.scan_btn.setMinimumHeight(40)
        self.scan_btn.clicked.connect(self.start_recon)
        
        self.clear_btn = QPushButton("🗑️ Clear")
        self.clear_btn.setMinimumHeight(40)
        self.clear_btn.clicked.connect(self.clear_results)
        
        input_layout.addWidget(self.domain_input, 3)
        input_layout.addWidget(self.scan_btn, 1)
        input_layout.addWidget(self.clear_btn, 1)
        
        main_layout.addLayout(input_layout)
        
        # ============ PROGRESS BAR ============
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setMinimumHeight(10)
        main_layout.addWidget(self.progress)
        
        # ============ TAB WIDGET ============
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)
        
        self.whois_tab = self.create_whois_tab()
        self.tabs.addTab(self.whois_tab, "📋 WHOIS MA'LUMOTLARI")
        
        self.dns_tab = self.create_dns_tab()
        self.tabs.addTab(self.dns_tab, "🌐 DNS RECORDS")

        self.subdomain_tab = self.create_subdomain_tab()
        self.tabs.addTab(self.subdomain_tab, "🧭 SUBDOMAINS")

        self.osint_tab = self.create_osint_tab()
        self.tabs.addTab(self.osint_tab, "🕵️ OSINT")

        self.waf_tab = self.create_waf_tab()
        self.tabs.addTab(self.waf_tab, "🛡️ WAF/FIREWALL")

        self.nmap_tab = self.create_nmap_tab()
        self.tabs.addTab(self.nmap_tab, "🔌 NMAP PORTS")

        self.tech_tab = self.create_tech_tab()
        self.tabs.addTab(self.tech_tab, "🧩 TECH/CVE")

        self.tls_tab = self.create_tls_tab()
        self.tabs.addTab(self.tls_tab, "🔐 TLS")
        
        self.attack_tab = self.create_attack_tab()
        self.tabs.addTab(self.attack_tab, "⚔️ HUJUM VEKTORLARI")
        
        self.raw_tab = self.create_raw_tab()
        self.tabs.addTab(self.raw_tab, "📄 RAW OUTPUT")
        
        self.report_tab = self.create_report_tab()
        self.tabs.addTab(self.report_tab, "📊 HISOBOT")
        
        main_layout.addWidget(self.tabs)
        
        # ============ STATUS BAR ============
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("✅ Tizim tayyor | Domen kiriting va RECON START bosing")
        
        self.worker = None
        self.thread = None
        self.dns_worker = None
        self.dns_thread = None
        self.last_results = {}
        
    def create_whois_tab(self):
        """WHOIS ma'lumotlari tabi"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        whois_group = QGroupBox("📋 DOMAIN REGISTRATION INFORMATION")
        grid = QGridLayout()
        
        labels = [
            "Domain:", "Registrar:", "Registrar URL:", "Registrar IANA ID:",
            "Creation Date:", "Updated Date:", "Expiry Date:",
            "DNSSEC:", "Domain Status:"
        ]
        
        self.whois_values = {}
        row = 0
        for label in labels:
            lbl = QLabel(label)
            lbl.setStyleSheet("font-weight: bold; color: #ff4444;")
            value = QLabel("⏳ Kutilmoqda...")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value.setStyleSheet("background-color: #1e1e1e; padding: 5px; border-radius: 3px;")
            grid.addWidget(lbl, row, 0)
            grid.addWidget(value, row, 1)
            self.whois_values[label] = value
            row += 1
        
        abuse_lbl = QLabel("Abuse Email/Phone:")
        abuse_lbl.setStyleSheet("font-weight: bold; color: #ff4444;")
        self.abuse_value = QLabel("⏳ Kutilmoqda...")
        self.abuse_value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.abuse_value.setStyleSheet("background-color: #1e1e1e; padding: 5px; border-radius: 3px;")
        grid.addWidget(abuse_lbl, row, 0)
        grid.addWidget(self.abuse_value, row, 1)
        
        whois_group.setLayout(grid)
        layout.addWidget(whois_group)
        
        ns_group = QGroupBox("🌍 NAME SERVERS (DNS)")
        ns_layout = QVBoxLayout()
        self.ns_list = QListWidget()
        self.ns_list.setStyleSheet("""
            QListWidget {
                background-color: #1e1e1e;
                color: #00ff00;
                font-family: monospace;
                border: 1px solid #ff4444;
            }
        """)
        ns_layout.addWidget(self.ns_list)
        ns_group.setLayout(ns_layout)
        layout.addWidget(ns_group)
        
        tab.setLayout(layout)
        return tab
    
    def create_dns_tab(self):
        """DNS Records tabi"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA']
        
        toolbar = QHBoxLayout()
        self.dns_type_combo = QComboBox()
        self.dns_type_combo.addItems(record_types)
        self.dns_type_combo.setMinimumHeight(30)
        
        check_btn = QPushButton("🔍 Tekshirish")
        check_btn.setMinimumHeight(30)
        check_btn.clicked.connect(self.check_specific_dns)
        
        scan_all_btn = QPushButton("⚡ Barchasini skanerlash")
        scan_all_btn.setMinimumHeight(30)
        scan_all_btn.clicked.connect(self.scan_all_dns)
        
        toolbar.addWidget(QLabel("DNS Record:"))
        toolbar.addWidget(self.dns_type_combo)
        toolbar.addWidget(check_btn)
        toolbar.addWidget(scan_all_btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)
        
        dns_group = QGroupBox("📡 DNS TEKSHIRUV NATIJALARI")
        dns_layout = QVBoxLayout()
        
        self.dns_tree = QTreeWidget()
        self.dns_tree.setHeaderLabels(["Record Type", "Value", "TTL", "Status"])
        self.dns_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #1e1e1e;
                color: #00ff00;
                font-family: monospace;
                border: 1px solid #ff4444;
            }
            QTreeWidget::item {
                padding: 5px;
            }
        """)
        self.configure_tree(self.dns_tree)
        
        dns_layout.addWidget(self.dns_tree)
        dns_group.setLayout(dns_layout)
        layout.addWidget(dns_group)
        
        tab.setLayout(layout)
        return tab

    def create_subdomain_tab(self):
        """Passive subdomain natijalari tabi"""
        tab = QWidget()
        layout = QVBoxLayout()

        summary_layout = QHBoxLayout()
        self.subdomain_count_label = QLabel("Topilgan: 0")
        self.subdomain_source_label = QLabel("Manba: subfinder (agar mavjud) + public passive sources")
        self.subdomain_count_label.setStyleSheet("font-weight: bold; color: #00ff00;")
        self.subdomain_source_label.setStyleSheet("color: #ffaa00;")
        summary_layout.addWidget(self.subdomain_count_label)
        summary_layout.addWidget(self.subdomain_source_label)
        summary_layout.addStretch()
        layout.addLayout(summary_layout)

        self.subdomain_list = QListWidget()
        self.subdomain_list.setStyleSheet("""
            QListWidget {
                background-color: #1e1e1e;
                color: #00ff00;
                font-family: monospace;
                border: 1px solid #ff4444;
            }
            QListWidget::item {
                padding: 6px;
                border-bottom: 1px solid #333333;
            }
        """)
        layout.addWidget(self.subdomain_list)

        tab.setLayout(layout)
        return tab

    def create_osint_tab(self):
        """Faqat passive OSINT natijalari tabi"""
        tab = QWidget()
        layout = QVBoxLayout()

        summary_layout = QHBoxLayout()
        self.osint_summary_label = QLabel("Passive OSINT: 0 item")
        self.osint_mode_label = QLabel("Mode: passive only")
        self.osint_summary_label.setStyleSheet("font-weight: bold; color: #00ff00;")
        self.osint_mode_label.setStyleSheet("color: #ffaa00;")
        summary_layout.addWidget(self.osint_summary_label)
        summary_layout.addWidget(self.osint_mode_label)
        summary_layout.addStretch()
        layout.addLayout(summary_layout)

        self.osint_tree = QTreeWidget()
        self.osint_tree.setHeaderLabels(["Category", "Value", "Source"])
        self.osint_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                font-family: monospace;
                border: 1px solid #ff4444;
            }
            QTreeWidget::item {
                padding: 5px;
            }
        """)
        self.configure_tree(self.osint_tree)
        layout.addWidget(self.osint_tree)

        tab.setLayout(layout)
        return tab

    def create_waf_tab(self):
        """Firewall/WAF/CDN fingerprint natijalari tabi"""
        tab = QWidget()
        layout = QVBoxLayout()

        summary_layout = QHBoxLayout()
        self.waf_summary_label = QLabel("WAF/CDN: tekshirilmagan")
        self.waf_confidence_label = QLabel("Confidence: 0%")
        self.waf_summary_label.setStyleSheet("font-weight: bold; color: #00ff00;")
        self.waf_confidence_label.setStyleSheet("color: #ffaa00;")
        summary_layout.addWidget(self.waf_summary_label)
        summary_layout.addWidget(self.waf_confidence_label)
        summary_layout.addStretch()
        layout.addLayout(summary_layout)

        self.waf_tree = QTreeWidget()
        self.waf_tree.setHeaderLabels(["Type", "Value", "Evidence"])
        self.waf_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                font-family: monospace;
                border: 1px solid #ff4444;
            }
            QTreeWidget::item {
                padding: 5px;
            }
        """)
        self.configure_tree(self.waf_tree)
        layout.addWidget(self.waf_tree)

        tab.setLayout(layout)
        return tab

    def create_nmap_tab(self):
        """Nmap ochiq portlar tabi"""
        tab = QWidget()
        layout = QVBoxLayout()

        summary_layout = QHBoxLayout()
        self.nmap_summary_label = QLabel("Open ports: tekshirilmagan")
        self.nmap_target_label = QLabel("Top 100 TCP ports")
        self.nmap_summary_label.setStyleSheet("font-weight: bold; color: #00ff00;")
        self.nmap_target_label.setStyleSheet("color: #ffaa00;")
        summary_layout.addWidget(self.nmap_summary_label)
        summary_layout.addWidget(self.nmap_target_label)
        summary_layout.addStretch()
        layout.addLayout(summary_layout)

        self.nmap_tree = QTreeWidget()
        self.nmap_tree.setHeaderLabels(["Port", "Protocol", "Service", "State"])
        self.nmap_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                font-family: monospace;
                border: 1px solid #ff4444;
            }
            QTreeWidget::item {
                padding: 5px;
            }
        """)
        self.configure_tree(self.nmap_tree)
        layout.addWidget(self.nmap_tree)

        tab.setLayout(layout)
        return tab

    def create_tech_tab(self):
        """Texnologiyalar va CVE natijalari tabi"""
        tab = QWidget()
        layout = QVBoxLayout()

        summary_layout = QHBoxLayout()
        self.tech_summary_label = QLabel("Technologies: tekshirilmagan")
        self.cve_summary_label = QLabel("CVEs: tekshirilmagan")
        self.tech_summary_label.setStyleSheet("font-weight: bold; color: #00ff00;")
        self.cve_summary_label.setStyleSheet("color: #ffaa00;")
        summary_layout.addWidget(self.tech_summary_label)
        summary_layout.addWidget(self.cve_summary_label)
        summary_layout.addStretch()
        layout.addLayout(summary_layout)

        self.tech_tree = QTreeWidget()
        self.tech_tree.setHeaderLabels(["Type", "Value", "Source"])
        self.tech_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                font-family: monospace;
                border: 1px solid #ff4444;
            }
            QTreeWidget::item {
                padding: 5px;
            }
        """)
        self.configure_tree(self.tech_tree)
        layout.addWidget(self.tech_tree)

        tab.setLayout(layout)
        return tab

    def create_tls_tab(self):
        """TLS sertifikat va cipher tabi"""
        tab = QWidget()
        layout = QVBoxLayout()

        self.tls_summary_label = QLabel("TLS: tekshirilmagan")
        self.tls_summary_label.setStyleSheet("font-weight: bold; color: #00ff00;")
        layout.addWidget(self.tls_summary_label)

        self.tls_tree = QTreeWidget()
        self.tls_tree.setHeaderLabels(["Field", "Value", "Source"])
        self.tls_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                font-family: monospace;
                border: 1px solid #ff4444;
            }
            QTreeWidget::item {
                padding: 5px;
            }
        """)
        self.configure_tree(self.tls_tree)
        layout.addWidget(self.tls_tree)

        tab.setLayout(layout)
        return tab
    
    def create_attack_tab(self):
        """Hujum vektorlari tabi"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        attack_group = QGroupBox("⚔️ ANIQLANGAN HUJUM VEKTORLARI")
        attack_layout = QVBoxLayout()
        
        self.attack_list = QListWidget()
        self.attack_list.setStyleSheet("""
            QListWidget {
                background-color: #1a1a1a;
                color: #ff8888;
                font-size: 12px;
                border: 2px solid #ff0000;
            }
            QListWidget::item {
                padding: 10px;
                border-bottom: 1px solid #333333;
            }
        """)
        
        attack_layout.addWidget(self.attack_list)
        attack_group.setLayout(attack_layout)
        layout.addWidget(attack_group)
        
        cmd_group = QGroupBox("💻 TAVSIYA ETILGAN BUYRUVLAR")
        cmd_layout = QVBoxLayout()
        
        self.cmd_text = QTextEdit()
        self.cmd_text.setFont(QFont("Courier New", 10))
        self.cmd_text.setStyleSheet("""
            QTextEdit {
                background-color: black;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 10px;
            }
        """)
        
        cmd_layout.addWidget(self.cmd_text)
        cmd_group.setLayout(cmd_layout)
        layout.addWidget(cmd_group)
        
        tab.setLayout(layout)
        return tab
    
    def create_raw_tab(self):
        """Raw output tabi"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        self.raw_output = QTextEdit()
        self.raw_output.setFont(QFont("Courier New", 10))
        self.raw_output.setStyleSheet("""
            QTextEdit {
                background-color: black;
                color: #ffffff;
                border: 1px solid #444444;
            }
        """)
        
        layout.addWidget(self.raw_output)
        tab.setLayout(layout)
        return tab
    
    def create_report_tab(self):
        """Hisobot tabi"""
        tab = QWidget()
        layout = QVBoxLayout()
        
        options_group = QGroupBox("📊 HISOBOT YARATISH")
        options_layout = QHBoxLayout()
        
        save_btn = QPushButton("💾 JSON hisobot saqlash")
        save_btn.setMinimumHeight(40)
        save_btn.clicked.connect(self.save_json_report)
        
        save_txt_btn = QPushButton("📄 TXT hisobot saqlash")
        save_txt_btn.setMinimumHeight(40)
        save_txt_btn.clicked.connect(self.save_txt_report)
        
        copy_btn = QPushButton("📋 Hammasini nusxalash")
        copy_btn.setMinimumHeight(40)
        copy_btn.clicked.connect(self.copy_all_results)
        
        options_layout.addWidget(save_btn)
        options_layout.addWidget(save_txt_btn)
        options_layout.addWidget(copy_btn)
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        preview_group = QGroupBox("📋 HISOBOT PREVIEW")
        preview_layout = QVBoxLayout()
        
        self.report_preview = QTextEdit()
        self.report_preview.setFont(QFont("Courier New", 10))
        self.report_preview.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #ff4444;
            }
        """)
        
        preview_layout.addWidget(self.report_preview)
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)
        
        tab.setLayout(layout)
        return tab
    
    def setup_style(self):
        """Qorong'i tema"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2d2d2d;
                color: #ffffff;
            }
            QWidget {
                background-color: #2d2d2d;
                color: #ffffff;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #ff4444;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                color: #ff4444;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QLineEdit {
                background-color: #1e1e1e;
                color: #00ff00;
                border: 2px solid #ff4444;
                border-radius: 5px;
                padding: 8px;
                font-size: 14px;
            }
            QPushButton {
                background-color: #ff4444;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 15px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #ff6666;
            }
            QPushButton:pressed {
                background-color: #cc0000;
            }
            QTabWidget::pane {
                border: 2px solid #ff4444;
                background-color: #1e1e1e;
            }
            QTabBar::tab {
                background-color: #333333;
                color: white;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #ff4444;
            }
            QTabBar::tab:hover {
                background-color: #555555;
            }
            QProgressBar {
                border: 2px solid #ff4444;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #ff4444;
                border-radius: 3px;
            }
        """)
    
    def start_recon(self):
        """Reconnaissance boshlash"""
        if self.thread is not None:
            QMessageBox.information(self, "Kutilmoqda", "Recon tekshiruv allaqachon ishlayapti")
            return

        try:
            domain = normalize_domain(self.domain_input.text())
        except ValueError as e:
            QMessageBox.warning(self, "Xatolik", str(e))
            return
        self.domain_input.setText(domain)
        
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.scan_btn.setEnabled(False)
        self.status_bar.showMessage(f"🔍 Skanerlanmoqda: {domain}...")
        
        self.worker = ReconWorker(domain)
        self.thread = QThread()
        self.worker.moveToThread(self.thread)
        
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.update_results)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.error.connect(self.thread.quit)
        self.worker.error.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(self.cleanup_recon_thread)
        self.worker.error.connect(self.handle_error)
        
        self.thread.start()
    
    def update_results(self, results):
        """Natijalarni UI ga yangilash"""
        self.progress.setVisible(False)
        self.scan_btn.setEnabled(True)
        self.last_results = results
        
        domain = results.get('domain', '')
        whois_data = results.get('whois', {})
        dns_data = results.get('dns', {})
        subdomains = results.get('subdomains', [])
        osint_data = results.get('osint', {})
        waf_data = results.get('waf', {})
        nmap_data = results.get('nmap', {})
        tech_data = results.get('technologies', {})
        cve_data = results.get('cves', {})
        tls_data = results.get('tls', {})
        attack_vectors = results.get('attack_vectors', [])
        raw_whois = results.get('raw_whois', '')
        
        # ============ WHOIS TAB ============
        if whois_data:
            self.whois_values["Domain:"].setText(domain)
            self.whois_values["Registrar:"].setText(self.safe_str(whois_data.get('registrar', '❌ Topilmadi')))
            self.whois_values["Registrar URL:"].setText(self.safe_str(whois_data.get('registrar_url', '❌ Topilmadi')))
            self.whois_values["Registrar IANA ID:"].setText(self.safe_str(whois_data.get('registrar_iana_id', '❌ Topilmadi')))
            
            self.whois_values["Creation Date:"].setText(self.safe_date(whois_data.get('creation_date')))
            self.whois_values["Updated Date:"].setText(self.safe_date(whois_data.get('updated_date')))
            self.whois_values["Expiry Date:"].setText(self.safe_date(whois_data.get('expiration_date')))
            
            self.whois_values["DNSSEC:"].setText(self.safe_str(whois_data.get('dnssec', 'unsigned')))
            
            status = whois_data.get('status', [])
            if status:
                if isinstance(status, list):
                    status_text = '\n'.join([str(s) for s in status if s])
                else:
                    status_text = str(status)
                self.whois_values["Domain Status:"].setText(status_text if status_text else '❌ Topilmadi')
            else:
                self.whois_values["Domain Status:"].setText('❌ Topilmadi')
            
            # Abuse contact
            abuse = []
            if whois_data.get('abuse_email'):
                abuse.append(f"📧 {whois_data['abuse_email']}")
            if whois_data.get('abuse_phone'):
                abuse.append(f"📞 {whois_data['abuse_phone']}")
            
            self.abuse_value.setText('\n'.join(abuse) if abuse else '🔒 Yashirilgan (GDPR)')
            
            # Name servers
            self.ns_list.clear()
            ns = whois_data.get('name_servers', [])
            if ns:
                if isinstance(ns, str):
                    ns = [ns]
                for server in ns:
                    if server:
                        item = QListWidgetItem(f"• {server}")
                        if 'cloudflare' in str(server).lower():
                            item.setForeground(QColor('#ffaa00'))
                        else:
                            item.setForeground(QColor('#00ff00'))
                        self.ns_list.addItem(item)
            else:
                self.ns_list.addItem("❌ Name serverlar topilmadi")
        
        # ============ DNS TAB ============
        self.dns_tree.clear()
        dns_count = 0
        for record_type, records in dns_data.items():
            if records:
                for record in records:
                    dns_count += 1
                    item = QTreeWidgetItem([
                        record_type, 
                        self.safe_str(record.get('value', '')), 
                        self.safe_str(record.get('ttl', '?')), 
                        '✅ Active'
                    ])
                    if record_type in ['A', 'AAAA']:
                        item.setForeground(0, QColor('#88ff88'))
                    elif record_type == 'MX':
                        item.setForeground(0, QColor('#ffaa88'))
                    elif record_type == 'TXT':
                        item.setForeground(0, QColor('#8888ff'))
                    self.dns_tree.addTopLevelItem(item)
        if dns_count == 0:
            self.dns_tree.addTopLevelItem(QTreeWidgetItem(["-", "DNS record topilmadi yoki resolver javob bermadi", "-", ""]))

        # ============ SUBDOMAINS TAB ============
        self.subdomain_list.clear()
        self.subdomain_count_label.setText(f"Topilgan: {len(subdomains)}")
        if subdomains:
            display_limit = 1000
            for subdomain in subdomains[:display_limit]:
                item = QListWidgetItem(f"• {subdomain}")
                item.setForeground(QColor('#00ff00'))
                self.subdomain_list.addItem(item)
            if len(subdomains) > display_limit:
                more = QListWidgetItem(f"... yana {len(subdomains) - display_limit} ta subdomain RAW/JSON hisobotda bor")
                more.setForeground(QColor('#ffaa00'))
                self.subdomain_list.addItem(more)
        else:
            self.subdomain_list.addItem("❌ Passive manbalarda subdomain topilmadi")

        # ============ OSINT TAB ============
        self.populate_osint_tree(osint_data)

        # ============ WAF/FIREWALL TAB ============
        self.populate_waf_tree(waf_data)

        # ============ NMAP PORTS TAB ============
        self.populate_nmap_tree(nmap_data)

        # ============ TECH/CVE TAB ============
        self.populate_tech_tree(tech_data, cve_data)

        # ============ TLS TAB ============
        self.populate_tls_tree(tls_data)
        
        # ============ ATTACK VECTORS TAB ============
        self.attack_list.clear()
        for vector in attack_vectors:
            item = QListWidgetItem(f"⚠️ {vector}")
            if 'CRITICAL' in vector:
                item.setForeground(QColor('#ff0000'))
                item.setBackground(QColor('#330000'))
            elif 'HIGH' in vector:
                item.setForeground(QColor('#ffaa00'))
            else:
                item.setForeground(QColor('#ffff00'))
            self.attack_list.addItem(item)
        
        # ============ COMMANDS ============
        commands = f"""# Domen: {domain}
# ================ WHOIS TEKSHIRUV ================
whois {domain}

# ================ DNS TEKSHIRUV ================
        dig {domain} A +short
        dig {domain} AAAA +short
        dig {domain} MX +short
        dig {domain} TXT +short
        dig {domain} NS +short
        dig {domain} CAA +short

# ================ SUBDOMAIN TEKSHIRUV ================
subfinder -silent -all -d {domain}
crt.sh/?q=%.{domain}&output=json
dnsrecon -d {domain}
sublist3r -d {domain}
amass enum -d {domain}

# ================ TRANSPORT TEKSHIRUV ================
nmap -Pn -T3 --top-ports 100 --open {domain}

# ================ WEB TEKSHIRUV ================
whatweb {domain}
nikto -h {domain}

# ================ SSL/TLS TEKSHIRUV ================
sslscan {domain}
testssl.sh {domain}

# ================ CLOUDFLARE ORQA IP TOPISH ================
# Origin IP topish usullari:
# 1. SecurityTrails (history)
# 2. crt.sh
# 3. Shodan
# 4. subdomain enumeration
"""
        self.cmd_text.setText(commands)
        
        # ============ RAW OUTPUT ============
        raw_text = f"""DOMAIN: {domain}
SCAN TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

=== RAW WHOIS MA'LUMOTLARI ===
{raw_whois}

=== PARSED WHOIS MA'LUMOTLARI ===
{json.dumps(whois_data, default=str, indent=2, ensure_ascii=False)}

=== DNS MA'LUMOTLARI ===
{json.dumps(dns_data, default=str, indent=2, ensure_ascii=False)}

=== PASSIVE SUBDOMAINLAR ===
{chr(10).join(['- ' + subdomain for subdomain in subdomains])}

=== PASSIVE OSINT ===
{json.dumps(osint_data, default=str, indent=2, ensure_ascii=False)}

=== WAF/FIREWALL ANIQLASH ===
{json.dumps(waf_data, default=str, indent=2, ensure_ascii=False)}

=== NMAP OPEN PORTS ===
{json.dumps(nmap_data, default=str, indent=2, ensure_ascii=False)}

=== TECHNOLOGIES ===
{json.dumps(tech_data, default=str, indent=2, ensure_ascii=False)}

=== CVE RESULTS ===
{json.dumps(cve_data, default=str, indent=2, ensure_ascii=False)}

=== TLS CERTIFICATE/CIPHER ===
{json.dumps(tls_data, default=str, indent=2, ensure_ascii=False)}

=== HUJUM VEKTORLARI ===
{chr(10).join(['- ' + v for v in attack_vectors])}
"""
        self.raw_output.setText(raw_text)
        
        # ============ REPORT PREVIEW ============
        report = f"""
╔══════════════════════════════════════════════════════════╗
║     PENTEST RECON REPORT - {domain}
║     Sana: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
╚══════════════════════════════════════════════════════════╝

[+] DOMAIN: {domain}
[+] REGISTRAR: {self.safe_str(whois_data.get('registrar', 'N/A'))}
[+] REGISTRAR IANA ID: {self.safe_str(whois_data.get('registrar_iana_id', 'N/A'))}
[+] CREATED: {self.safe_date(whois_data.get('creation_date'))}
[+] EXPIRY: {self.safe_date(whois_data.get('expiration_date'))}
[+] DNSSEC: {self.safe_str(whois_data.get('dnssec', 'unsigned'))}

[+] ABUSE CONTACT:
  • 📧 {self.safe_str(whois_data.get('abuse_email', 'N/A'))}
  • 📞 {self.safe_str(whois_data.get('abuse_phone', 'N/A'))}

[+] NAME SERVERS:
{chr(10).join(['  • ' + self.safe_str(ns) for ns in whois_data.get('name_servers', []) if ns])}

[+] A RECORDS (IP):
{chr(10).join(['  • ' + self.safe_str(r.get('value', '')) for r in dns_data.get('A', [])])}

[+] MX RECORDS (MAIL):
{chr(10).join(['  • ' + self.safe_str(r.get('value', '')) for r in dns_data.get('MX', [])])}

[+] TXT RECORDS:
{chr(10).join(['  • ' + self.safe_str(r.get('value', '')) for r in dns_data.get('TXT', [])])}

[+] PASSIVE SUBDOMAINS ({len(subdomains)}):
{chr(10).join(['  • ' + subdomain for subdomain in subdomains[:100]])}

[+] PASSIVE OSINT:
  • Emails: {len(osint_data.get('emails', []))}
  • URLs: {len(osint_data.get('urls', []))}
  • Interesting files: {len(osint_data.get('interesting_urls', []))}
  • Source hits: {len([s for s in osint_data.get('sources', []) if s.get('count', 0) > 0])}

[+] WAF/FIREWALL:
  • Detected: {self.safe_str(waf_data.get('detected', False))}
  • Provider: {self.safe_str(waf_data.get('provider', 'N/A'))}
  • Confidence: {self.safe_str(waf_data.get('confidence', 0))}%

[+] NMAP OPEN PORTS:
{chr(10).join(['  • {}/{} {} {}'.format(p.get('port'), p.get('protocol'), p.get('service'), p.get('state')) for p in nmap_data.get('open_ports', [])])}

[+] TECHNOLOGIES:
{chr(10).join(['  • {} ({})'.format(t.get('name'), t.get('category')) for t in tech_data.get('technologies', [])])}

[+] CVE:
  • {self.safe_str(cve_data.get('message', 'N/A'))}

[+] TLS:
  • Status: {self.safe_str(tls_data.get('status', 'N/A'))}
  • Cipher: {self.safe_str(tls_data.get('cipher', {}).get('name', 'N/A'))}
  • Protocol: {self.safe_str(tls_data.get('cipher', {}).get('protocol', 'N/A'))}

[!] ANIQLANGAN ZAIFLIKLAR:
{chr(10).join(['  • ' + v for v in attack_vectors])}

[!] TAVSIYALAR:
{chr(10).join(['  • ' + v for v in self.generate_recommendations(attack_vectors)])}

════════════════════════════════════════════════════════════
"""
        self.report_preview.setText(report)
        
        self.status_bar.showMessage(
            f"✅ Skanerlash tugadi: {domain} | {len(subdomains)} subdomain | {len(attack_vectors)} ta zaiflik",
            10000
        )

    def populate_osint_tree(self, osint_data):
        """Passive OSINT natijalarini daraxt ko'rinishida chiqarish"""
        self.osint_tree.clear()
        summary = osint_data.get('summary', {})
        total_items = sum([
            summary.get('subdomains', 0),
            summary.get('emails', 0),
            summary.get('urls', 0),
            summary.get('interesting_urls', 0),
            summary.get('takeover_hints', 0),
        ])
        self.osint_summary_label.setText(f"Passive OSINT: {total_items} item")
        source_rows = [
            (
                source.get('name', ''),
                f"{source.get('count', 0)} item",
                self.compact_status(source.get('status', 'unknown')),
            )
            for source in osint_data.get('sources', [])
        ]
        self.add_tree_section(self.osint_tree, "Summary", [(key, value, "computed") for key, value in summary.items()])
        self.add_tree_section(self.osint_tree, "Sources", source_rows)
        self.add_tree_section(self.osint_tree, "Emails", [(email, "", "passive text") for email in osint_data.get('emails', [])], expanded=False)
        self.add_tree_section(self.osint_tree, "Interesting URLs", [(url, "", "passive URL") for url in osint_data.get('interesting_urls', [])[:200]])
        self.add_tree_section(self.osint_tree, "URLs", [(url, "", "Wayback/URLScan") for url in osint_data.get('urls', [])[:300]], expanded=False)
        self.add_tree_section(self.osint_tree, "Passive Hosts", [
            (item.get('type', ''), item.get('value', ''), item.get('source', 'passive'))
            for item in osint_data.get('infra', [])[:300]
        ], expanded=False)
        self.add_tree_section(self.osint_tree, "Takeover Hints", [
            (item.get('host', ''), item.get('hint', ''), item.get('source', 'passive DNS'))
            for item in osint_data.get('takeover_hints', [])
        ])

    def populate_waf_tree(self, waf_data):
        """WAF/CDN aniqlash natijalarini ko'rsatish"""
        self.waf_tree.clear()
        provider = waf_data.get('provider') or 'Aniqlanmadi'
        confidence = int(waf_data.get('confidence', 0) or 0)
        detected = bool(waf_data.get('detected'))
        self.waf_summary_label.setText(f"WAF/CDN: {provider if detected else 'aniqlanmadi'}")
        self.waf_confidence_label.setText(f"Confidence: {confidence}%")
        self.add_tree_section(self.waf_tree, "Summary", [
            ("Detected", "Yes" if detected else "No", "computed"),
            ("Provider", provider, "fingerprint"),
            ("Confidence", f"{confidence}%", "score"),
            ("HTTP Status", waf_data.get('http_status', 'N/A'), waf_data.get('url', '')),
        ])
        self.add_tree_section(self.waf_tree, "Evidence", [
            (item.get('provider', provider), item.get('value', ''), f"{item.get('type', '')}: {item.get('evidence', '')}")
            for item in waf_data.get('evidence', [])
        ])
        self.add_tree_section(self.waf_tree, "Important Headers", [
            (key, value, "HTTP response")
            for key, value in waf_data.get('headers', {}).items()
            if key.lower() in ("server", "x-powered-by", "cf-ray", "x-cache", "x-amz-cf-id", "x-sucuri-id", "x-iinfo")
        ], expanded=False)
        self.add_tree_section(self.waf_tree, "Notes", [(self.compact_status(note), "", "analysis") for note in waf_data.get('notes', [])], expanded=False)

    def populate_nmap_tree(self, nmap_data):
        """Nmap ochiq port natijalarini ko'rsatish"""
        self.nmap_tree.clear()
        open_ports = nmap_data.get('open_ports', [])
        status = nmap_data.get('status', 'not_run')
        self.nmap_summary_label.setText(f"Open ports: {len(open_ports)}")
        self.nmap_target_label.setText(self.safe_str(nmap_data.get('target', 'Top 100 TCP ports')))

        if status != 'ok':
            item = QTreeWidgetItem(["Status", "-", self.compact_status(nmap_data.get('message', status)), ""])
            item.setForeground(0, QColor('#ffaa00'))
            self.nmap_tree.addTopLevelItem(item)
            return

        if not open_ports:
            self.nmap_tree.addTopLevelItem(QTreeWidgetItem(["-", "tcp", "Ochiq port topilmadi", "closed/filtered"]))
            return

        for port in open_ports:
            service = port.get('service') or "unknown"
            product = " ".join([str(port.get('product', '')).strip(), str(port.get('version', '')).strip()]).strip()
            item = QTreeWidgetItem([
                self.safe_str(port.get('port')),
                self.safe_str(port.get('protocol')),
                self.safe_str(service if not product else f"{service} | {product}"),
                self.safe_str(port.get('state')),
            ])
            item.setForeground(0, QColor('#00ff00'))
            self.nmap_tree.addTopLevelItem(item)

    def populate_tech_tree(self, tech_data, cve_data):
        """Texnologiya va CVE natijalarini ko'rsatish"""
        self.tech_tree.clear()
        technologies = tech_data.get('technologies', [])
        cve_items = cve_data.get('items', [])
        cve_count = sum(len(item.get('cves', [])) for item in cve_items)
        self.tech_summary_label.setText(f"Technologies: {len(technologies)}")
        self.cve_summary_label.setText(f"CVEs: {cve_count}")
        self.add_tree_section(self.tech_tree, "Sources", [
            (source.get('name', ''), self.compact_status(source.get('status', '')), source.get('count', ''))
            for source in tech_data.get('sources', [])
        ])
        self.add_tree_section(self.tech_tree, "Technologies", [
            (tech.get('name', ''), tech.get('category', ''), tech.get('source', ''))
            for tech in technologies
        ])
        cve_rows = [
            (
                cve.get('id', ''),
                item.get('technology', ''),
                f"score={cve.get('score') or 'N/A'} | {cve.get('published', '')}"
            )
            for item in cve_items
            for cve in item.get('cves', [])
        ]
        if not cve_rows and cve_data.get('message'):
            cve_rows = [("Status", self.compact_status(cve_data.get('message')), cve_data.get('status', ''))]
        self.add_tree_section(self.tech_tree, "CVE Matches", cve_rows)

    def populate_tls_tree(self, tls_data):
        """TLS sertifikat va cipher natijalarini ko'rsatish"""
        self.tls_tree.clear()
        status = tls_data.get('status', 'tekshirilmagan')
        cipher = tls_data.get('cipher', {})
        cert = tls_data.get('certificate', {})
        self.tls_summary_label.setText(
            f"TLS: {self.safe_str(status)} | {self.safe_str(cipher.get('protocol', ''))} | {self.safe_str(cipher.get('name', ''))}"
        )
        cert_rows = []
        for key in ("subject", "issuer", "not_before", "not_after", "signature_hash", "serial_number"):
            if key in cert:
                cert_rows.append((key, cert.get(key), "cryptography"))
        if cert.get("san"):
            cert_rows.append(("SAN count", len(cert.get("san", [])), "cryptography"))
            cert_rows.extend(("SAN", name, "cryptography") for name in cert.get("san", [])[:20])
        self.add_tree_section(self.tls_tree, "Certificate", cert_rows)
        self.add_tree_section(self.tls_tree, "Cipher", [(key, value, "ssl") for key, value in cipher.items()])
        self.add_tree_section(self.tls_tree, "Issues", [(issue, "", "analysis") for issue in tls_data.get('issues', [])])
        self.add_tree_section(self.tls_tree, "Status", [("message", self.compact_status(tls_data.get('message', '')), "TLS")], expanded=False)

    def cleanup_recon_thread(self):
        """Recon worker obyektlariga havolalarni tozalash"""
        self.worker = None
        self.thread = None
    
    def safe_str(self, value):
        """Xavfsiz string converter"""
        if value is None:
            return '❌ Topilmadi'
        if value == '':
            return '❌ Topilmadi'
        if isinstance(value, list):
            return ', '.join([str(v) for v in value if v]) or '❌ Topilmadi'
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d %H:%M:%S')
        return str(value)

    def configure_tree(self, tree):
        """Natija jadvallarini o'qishga qulay qilish."""
        tree.setAlternatingRowColors(True)
        tree.setRootIsDecorated(True)
        tree.setUniformRowHeights(True)
        tree.header().setStretchLastSection(True)
        tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)

    def add_tree_section(self, tree, title, rows, expanded=True):
        """Bir xil section format: sarlavha, son va child qatorlar."""
        parent = QTreeWidgetItem([title, str(len(rows)), ""])
        parent.setForeground(0, QColor('#ffaa00'))
        tree.addTopLevelItem(parent)
        if not rows:
            child = QTreeWidgetItem(["-", "Ma'lumot topilmadi", ""])
            child.setForeground(1, QColor('#888888'))
            parent.addChild(child)
        else:
            for col1, col2, col3 in rows:
                parent.addChild(QTreeWidgetItem([
                    self.safe_str(col1),
                    self.safe_str(col2),
                    self.safe_str(col3),
                ]))
        parent.setExpanded(expanded)
        return parent

    def compact_status(self, status):
        """Uzoq xatolarni GUI uchun qisqartirish."""
        status = self.safe_str(status)
        replacements = {
            "HTTP Error 429: Too Many Requests": "rate limited",
            "HTTP Error 503: Service Unavailable": "service unavailable",
            "HTTP Error 500: Internal Server Error": "server error",
            "The read operation timed out": "timeout",
            "getaddrinfo failed": "DNS lookup failed",
        }
        for old, new in replacements.items():
            status = status.replace(old, new)
        if len(status) > 120:
            status = status[:117] + "..."
        return status
    
    def safe_date(self, date_value):
        """Sanalarni xavfsiz olish"""
        if date_value is None:
            return '❌ Topilmadi'
        if date_value == '':
            return '❌ Topilmadi'
        if date_value == '-':
            return '❌ Topilmadi'
        
        try:
            if isinstance(date_value, list):
                if date_value and date_value[0]:
                    if isinstance(date_value[0], datetime):
                        return date_value[0].strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        return str(date_value[0])
                return '❌ Topilmadi'
            
            if isinstance(date_value, datetime):
                return date_value.strftime('%Y-%m-%d %H:%M:%S')
            
            if isinstance(date_value, str):
                if 'T' in date_value:
                    return date_value.replace('T', ' ').replace('Z', '')
                return date_value
            
            return str(date_value)
            
        except Exception:
            return '❌ Topilmadi'
    
    def generate_recommendations(self, attack_vectors):
        """Zaifliklarga qarshi tavsiyalar"""
        recommendations = []
        
        if any('DNSSEC' in v for v in attack_vectors):
            recommendations.append("DNSSEC yoqish - DNS spoofing va cache poisoning oldini olish uchun")
        
        if any('Transfer' in v for v in attack_vectors):
            recommendations.append("Domain transfer himoyasini yoqish - clientTransferProhibited status")
        
        if any('Cloudflare' in v for v in attack_vectors):
            recommendations.append("Origin IP yashirish - faqat Cloudflare IP'lariga ruxsat berish")
            recommendations.append("Authenticated Origin Pulls yoqish")
        
        if any('SPF' in v for v in attack_vectors):
            recommendations.append("SPF, DKIM, DMARC yozuvlarini sozlash - email spoofing oldini olish")
        
        if not recommendations:
            recommendations.append("Muntazam xavfsizlik auditi o'tkazish")
            recommendations.append("Zero-day zaifliklar uchun monitoring")
        
        return recommendations
    
    def check_specific_dns(self):
        """Maxsus DNS record tekshirish"""
        try:
            domain = normalize_domain(self.domain_input.text())
        except ValueError as e:
            QMessageBox.warning(self, "Xatolik", str(e))
            return
        self.domain_input.setText(domain)
        record_type = self.dns_type_combo.currentText()
        self.start_dns_lookup(domain, [record_type], append=True)
    
    def scan_all_dns(self):
        """Barcha DNS recordlarni skanerlash"""
        try:
            domain = normalize_domain(self.domain_input.text())
        except ValueError as e:
            QMessageBox.warning(self, "Xatolik", str(e))
            return
        self.domain_input.setText(domain)
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA']
        self.start_dns_lookup(domain, record_types, append=False)

    def start_dns_lookup(self, domain, record_types, append):
        """DNS tekshiruvni UI threaddan tashqarida ishga tushirish"""
        if self.dns_thread is not None:
            QMessageBox.information(self, "Kutilmoqda", "DNS tekshiruv allaqachon ishlayapti")
            return

        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.dns_worker = DNSLookupWorker(domain, record_types)
        self.dns_thread = QThread()
        self.dns_worker.moveToThread(self.dns_thread)

        self.dns_thread.started.connect(self.dns_worker.run)
        self.dns_worker.finished.connect(lambda data: self.update_dns_lookup_results(data, append))
        self.dns_worker.error.connect(self.handle_dns_error)
        self.dns_worker.finished.connect(self.dns_thread.quit)
        self.dns_worker.error.connect(self.dns_thread.quit)
        self.dns_worker.finished.connect(self.dns_worker.deleteLater)
        self.dns_worker.error.connect(self.dns_worker.deleteLater)
        self.dns_thread.finished.connect(self.dns_thread.deleteLater)
        self.dns_thread.finished.connect(self.cleanup_dns_thread)

        self.status_bar.showMessage(f"🔍 DNS tekshirilmoqda: {domain}")
        self.dns_thread.start()

    def update_dns_lookup_results(self, dns_data, append):
        """DNS worker natijalarini UI ga chiqarish"""
        if not append:
            self.dns_tree.clear()

        found = 0
        for rtype, records in dns_data.items():
            for record in records:
                found += 1
                item = QTreeWidgetItem([
                    rtype,
                    self.safe_str(record.get('value', '')),
                    self.safe_str(record.get('ttl', '?')),
                    '✅ Active'
                ])
                self.dns_tree.addTopLevelItem(item)

        self.progress.setVisible(False)
        self.status_bar.showMessage(f"✅ DNS tekshiruv tugadi | {found} ta record topildi", 3000)

    def handle_dns_error(self, error_msg):
        """DNS worker xatolarini ko'rsatish"""
        self.progress.setVisible(False)
        QMessageBox.information(self, "DNS xatosi", error_msg)
        self.status_bar.showMessage(f"❌ DNS xatosi: {error_msg}", 7000)

    def cleanup_dns_thread(self):
        """DNS worker obyektlariga havolalarni tozalash"""
        self.dns_worker = None
        self.dns_thread = None
    
    def save_json_report(self):
        """JSON hisobot saqlash"""
        try:
            domain = normalize_domain(self.domain_input.text())
        except ValueError:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 
            "JSON hisobot saqlash",
            f"{domain}_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.last_results or {}, f, default=str, indent=2, ensure_ascii=False)
            QMessageBox.information(self, "✅ Saqlandi", f"Hisobot saqlandi:\n{filename}")
    
    def save_txt_report(self):
        """TXT hisobot saqlash"""
        try:
            domain = normalize_domain(self.domain_input.text())
        except ValueError:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "TXT hisobot saqlash",
            f"{domain}_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt)"
        )
        
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.report_preview.toPlainText())
            QMessageBox.information(self, "✅ Saqlandi", f"Hisobot saqlandi:\n{filename}")
    
    def copy_all_results(self):
        """Hamma natijalarni nusxalash"""
        clipboard = QApplication.clipboard()
        text = f"{self.raw_output.toPlainText()}\n\n{self.report_preview.toPlainText()}"
        clipboard.setText(text)
        self.status_bar.showMessage("📋 Natijalar clipboard'ga nusxalandi", 3000)
    
    def clear_results(self):
        """Natijalarni tozalash"""
        self.domain_input.clear()
        
        for label, widget in self.whois_values.items():
            widget.setText("⏳ Kutilmoqda...")
        self.abuse_value.setText("⏳ Kutilmoqda...")
        self.ns_list.clear()
        self.dns_tree.clear()
        self.subdomain_list.clear()
        self.subdomain_count_label.setText("Topilgan: 0")
        self.osint_tree.clear()
        self.osint_summary_label.setText("Passive OSINT: 0 item")
        self.waf_tree.clear()
        self.waf_summary_label.setText("WAF/CDN: tekshirilmagan")
        self.waf_confidence_label.setText("Confidence: 0%")
        self.nmap_tree.clear()
        self.nmap_summary_label.setText("Open ports: tekshirilmagan")
        self.nmap_target_label.setText("Top 100 TCP ports")
        self.tech_tree.clear()
        self.tech_summary_label.setText("Technologies: tekshirilmagan")
        self.cve_summary_label.setText("CVEs: tekshirilmagan")
        self.tls_tree.clear()
        self.tls_summary_label.setText("TLS: tekshirilmagan")
        self.attack_list.clear()
        self.cmd_text.clear()
        self.raw_output.clear()
        self.report_preview.clear()
        
        self.status_bar.showMessage("✅ Barcha natijalar tozalandi", 3000)
    
    def handle_error(self, error_msg):
        """Xatoliklarni boshqarish"""
        self.progress.setVisible(False)
        self.scan_btn.setEnabled(True)
        QMessageBox.critical(self, "Xatolik", f"❌ {error_msg}")
        self.status_bar.showMessage(f"❌ Xatolik: {error_msg}", 10000)



def main():
    import sys
    app = QApplication(sys.argv)
    app.setApplicationName("Pentest Recon Tool")
    app.setApplicationVersion("3.1")
    app.setOrganizationName("RedTeam")
    window = PentestWhoisGUI()
    window.show()
    sys.exit(app.exec())
