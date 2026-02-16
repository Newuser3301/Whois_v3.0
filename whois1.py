#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PENTEST RECON TOOL - WHOIS & DNS Analyzer v3.1
"""

import sys
import whois
import dns.resolver
import dns.exception
import subprocess
import json
import re
import socket
from datetime import datetime
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

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
        
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR', 'CAA']
        
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
        
        dns_layout.addWidget(self.dns_tree)
        dns_group.setLayout(dns_layout)
        layout.addWidget(dns_group)
        
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
        domain = self.domain_input.text().strip()
        
        if not domain:
            QMessageBox.warning(self, "Xatolik", "Iltimos, domen kiriting!")
            return
        
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
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.error.connect(self.handle_error)
        
        self.thread.start()
    
    def update_results(self, results):
        """Natijalarni UI ga yangilash"""
        self.progress.setVisible(False)
        self.scan_btn.setEnabled(True)
        
        domain = results.get('domain', '')
        whois_data = results.get('whois', {})
        dns_data = results.get('dns', {})
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
        for record_type, records in dns_data.items():
            if records:
                for record in records:
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
dig {domain} ANY +short
dig {domain} A +short
dig {domain} MX +short
dig {domain} TXT +short
dig {domain} NS +short

# ================ SUBDOMAIN TEKSHIRUV ================
dnsrecon -d {domain}
sublist3r -d {domain}
amass enum -d {domain}

# ================ TRANSPORT TEKSHIRUV ================
nmap -sS -sV -p- -T4 {domain}
nmap -sU --top-ports 100 {domain}

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

[!] ANIQLANGAN ZAIFLIKLAR:
{chr(10).join(['  • ' + v for v in attack_vectors])}

[!] TAVSIYALAR:
{chr(10).join(['  • ' + v for v in self.generate_recommendations(attack_vectors)])}

════════════════════════════════════════════════════════════
"""
        self.report_preview.setText(report)
        
        self.status_bar.showMessage(f"✅ Skanerlash tugadi: {domain} | {len(attack_vectors)} ta zaiflik aniqlandi", 10000)
    
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
                return date_value.strftime('%Y-%m-%d %M:%S')
            
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
        domain = self.domain_input.text().strip()
        record_type = self.dns_type_combo.currentText()
        
        if not domain:
            return
        
        try:
            answers = dns.resolver.resolve(domain, record_type)
            
            for answer in answers:
                item = QTreeWidgetItem([record_type, str(answer), str(answer.ttl) if hasattr(answer, 'ttl') else '?', '✅ Active'])
                self.dns_tree.addTopLevelItem(item)
                
            self.status_bar.showMessage(f"✅ {record_type} record topildi", 3000)
            
        except Exception as e:
            QMessageBox.information(self, "Natija", f"{record_type} record topilmadi")
    
    def scan_all_dns(self):
        """Barcha DNS recordlarni skanerlash"""
        domain = self.domain_input.text().strip()
        
        if not domain:
            return
        
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA']
        self.dns_tree.clear()
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                for answer in answers:
                    item = QTreeWidgetItem([rtype, str(answer), str(answer.ttl) if hasattr(answer, 'ttl') else '?', '✅ Active'])
                    self.dns_tree.addTopLevelItem(item)
            except:
                pass
        
        self.progress.setVisible(False)
        self.status_bar.showMessage(f"✅ Barcha DNS recordlar tekshirildi", 3000)
    
    def save_json_report(self):
        """JSON hisobot saqlash"""
        domain = self.domain_input.text().strip()
        if not domain:
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 
            "JSON hisobot saqlash",
            f"{domain}_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json)"
        )
        
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.raw_output.toPlainText())
            QMessageBox.information(self, "✅ Saqlandi", f"Hisobot saqlandi:\n{filename}")
    
    def save_txt_report(self):
        """TXT hisobot saqlash"""
        domain = self.domain_input.text().strip()
        if not domain:
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


class ReconWorker(QObject):
    """Reconnaissance ishchi thread - TO'LIQ TO'G'RILANGAN"""
    
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, domain):
        super().__init__()
        self.domain = domain
    
    def run(self):
        """Reconnaissance ishni bajarish"""
        try:
            # 1. WHOIS ma'lumotlarini olish
            whois_data, raw_whois = self.get_whois_info()
            
            # 2. DNS ma'lumotlarini olish
            dns_data = self.get_dns_records()
            
            # 3. Hujum vektorlarini tahlil qilish
            attack_vectors = self.analyze_attack_vectors(whois_data, dns_data)
            
            results = {
                'domain': self.domain,
                'whois': whois_data,
                'dns': dns_data,
                'attack_vectors': attack_vectors,
                'raw_whois': raw_whois
            }
            
            self.finished.emit(results)
            
        except Exception as e:
            self.error.emit(str(e))
    
    def get_whois_info(self):
        """WHOIS ma'lumotlarini olish - 100% ishlaydigan versiya"""
        whois_info = {
            'domain': self.domain,
            'registrar': None,
            'registrar_url': None,
            'creation_date': None,
            'updated_date': None,
            'expiration_date': None,
            'name_servers': [],
            'status': [],
            'dnssec': 'unsigned',
            'abuse_email': None,
            'abuse_phone': None,
            'registrar_iana_id': None,
            'whois_server': None
        }
        
        raw_whois = ""
        
        try:
            # 1. python-whois orqali olish
            w = whois.whois(self.domain)
            
            whois_info['registrar'] = w.registrar if hasattr(w, 'registrar') else None
            whois_info['registrar_url'] = w.registrar_url if hasattr(w, 'registrar_url') else None
            whois_info['creation_date'] = w.creation_date if hasattr(w, 'creation_date') else None
            whois_info['updated_date'] = w.updated_date if hasattr(w, 'updated_date') else None
            whois_info['expiration_date'] = w.expiration_date if hasattr(w, 'expiration_date') else None
            whois_info['name_servers'] = w.name_servers if hasattr(w, 'name_servers') else []
            whois_info['status'] = w.status if hasattr(w, 'status') else []
            whois_info['dnssec'] = w.dnssec if hasattr(w, 'dnssec') else 'unsigned'
            whois_info['whois_server'] = w.whois_server if hasattr(w, 'whois_server') else None
            
        except Exception as e:
            print(f"python-whois xatosi: {e}")
        
        # 2. SOCKET orqali to'g'ridan-to'g'ri WHOIS so'rovi
        try:
            raw_whois = self.get_raw_whois_socket(self.domain)
            
            # Abuse Email
            email_match = re.search(r'Registrar Abuse Contact Email:\s*([^\s]+@[^\s]+)', raw_whois, re.IGNORECASE)
            if email_match:
                whois_info['abuse_email'] = email_match.group(1)
            
            # Abuse Phone
            phone_match = re.search(r'Registrar Abuse Contact Phone:\s*([+\d\s.-]+)', raw_whois, re.IGNORECASE)
            if phone_match:
                whois_info['abuse_phone'] = phone_match.group(1).strip()
            
            # Registrar IANA ID
            iana_match = re.search(r'Registrar IANA ID:\s*(\d+)', raw_whois, re.IGNORECASE)
            if iana_match:
                whois_info['registrar_iana_id'] = iana_match.group(1)
            
            # Domain Status (agar python-whois olmagan bo'lsa)
            if not whois_info['status']:
                status_matches = re.findall(r'Domain Status:\s*(.+?)(?:\n|$)', raw_whois, re.IGNORECASE)
                if status_matches:
                    whois_info['status'] = [s.strip() for s in status_matches if s.strip()]
            
            # Name Servers (agar python-whois olmagan bo'lsa)
            if not whois_info['name_servers']:
                ns_matches = re.findall(r'Name Server:\s*(.+?)(?:\n|$)', raw_whois, re.IGNORECASE)
                if ns_matches:
                    whois_info['name_servers'] = [ns.strip() for ns in ns_matches if ns.strip()]
            
            # DNSSEC
            dnssec_match = re.search(r'DNSSEC:\s*(\S+)', raw_whois, re.IGNORECASE)
            if dnssec_match:
                whois_info['dnssec'] = dnssec_match.group(1).lower()
            
        except Exception as e:
            print(f"Socket WHOIS xatosi: {e}")
        
        return whois_info, raw_whois
    
    def get_raw_whois_socket(self, domain):
        """Socket orqali to'g'ridan-to'g'ri WHOIS so'rovi"""
        try:
            # .org domenlari uchun maxsus WHOIS server
            whois_server = "whois.publicinterestregistry.org"
            port = 43
            
            # Socket yaratish
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            # Ulanish
            sock.connect((whois_server, port))
            
            # So'rov yuborish
            request = f"{domain}\r\n"
            sock.send(request.encode())
            
            # Javobni olish
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            
            return response.decode('utf-8', errors='ignore')
            
        except Exception as e:
            print(f"Socket WHOIS xatosi: {e}")
            
            # Backup: whois komandasi (agar mavjud bo'lsa)
            try:
                result = subprocess.run(['whois', domain], 
                                      capture_output=True, text=True, timeout=5)
                return result.stdout
            except:
                return ""
    
    def get_dns_records(self):
        """Barcha DNS recordlarni olish"""
        dns_info = {}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA']
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, rtype)
                records = []
                
                for answer in answers:
                    record = {
                        'value': str(answer).rstrip('.'),
                        'ttl': answer.ttl if hasattr(answer, 'ttl') else '?'
                    }
                    
                    if rtype == 'MX' and hasattr(answer, 'preference'):
                        record['preference'] = answer.preference
                    
                    records.append(record)
                
                dns_info[rtype] = records
                
            except dns.resolver.NoAnswer:
                dns_info[rtype] = []
            except dns.resolver.NXDOMAIN:
                dns_info[rtype] = []
            except Exception:
                dns_info[rtype] = []
        
        return dns_info
    
    def analyze_attack_vectors(self, whois_data, dns_data):
        """Hujum vektorlarini tahlil qilish"""
        vectors = []
        
        try:
            # 1. DNSSEC tekshirish
            if not whois_data.get('dnssec') or whois_data.get('dnssec') == 'unsigned':
                vectors.append("🔴 CRITICAL: DNSSEC yoqilmagan - DNS spoofing xavfi")
            
            # 2. Transfer status
            status = whois_data.get('status', [])
            status_text = ''
            if isinstance(status, list):
                status_text = ' '.join([str(s).lower() for s in status if s])
            else:
                status_text = str(status).lower()
            
            if 'clienttransferprohibited' not in status_text:
                vectors.append("🟠 HIGH: Domain transfer himoyasi yo'q - domain hijacking mumkin")
            
            # 3. Cloudflare tekshirish
            ns_list = whois_data.get('name_servers', [])
            if isinstance(ns_list, str):
                ns_list = [ns_list]
            
            for ns in ns_list:
                if ns and 'cloudflare' in str(ns).lower():
                    vectors.append("🟡 MEDIUM: Cloudflare DNS aniqlangan - Origin IP topish imkoniyati")
                    break
            
            # 4. Registrar tekshirish
            registrar = whois_data.get('registrar', '')
            if registrar and ('openprovider' in str(registrar).lower() or 'registrar.eu' in str(registrar).lower()):
                vectors.append("🟡 MEDIUM: OpenProvider registrar - support phishing imkoniyati")
            
            # 5. Abuse contact mavjudligi
            if whois_data.get('abuse_email') or whois_data.get('abuse_phone'):
                vectors.append("🟢 INFO: Abuse contact mavjud - Social engineering imkoniyati")
            
            # 6. SPF tekshirish
            txt_records = dns_data.get('TXT', [])
            has_spf = False
            for txt in txt_records:
                txt_str = str(txt.get('value', '')).lower()
                if 'v=spf1' in txt_str:
                    has_spf = True
                    if '~all' in txt_str:
                        vectors.append("🟠 HIGH: SPF SoftFail (~all) - email spoofing imkoniyati")
                    elif '?all' in txt_str:
                        vectors.append("🟠 HIGH: SPF Neutral (?all) - email spoofing imkoniyati")
                    elif '-all' not in txt_str:
                        vectors.append("🟡 MEDIUM: SPF HardFail yo'q")
            
            if not has_spf:
                vectors.append("🔴 CRITICAL: SPF record yo'q - email spoofing mumkin")
            
            # 7. Origin IP ochiqligi
            a_records = dns_data.get('A', [])
            for a in a_records:
                ip = str(a.get('value', ''))
                # Cloudflare IP emas
                if ip and not (ip.startswith('104.') or ip.startswith('172.') or 
                              ip.startswith('103.') or ip.startswith('141.101.') or
                              ip.startswith('188.114.') or ip.startswith('162.159.')):
                    vectors.append(f"🟡 MEDIUM: Origin IP ochiq - {ip}")
            
            # 8. DMARC tekshirish
            try:
                dmarc_domain = f"_dmarc.{self.domain}"
                dmarc_answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                has_dmarc = False
                for answer in dmarc_answers:
                    if 'v=DMARC1' in str(answer):
                        has_dmarc = True
                        if 'p=reject' not in str(answer).lower():
                            vectors.append("🟡 MEDIUM: DMARC zaif sozlangan")
                if not has_dmarc:
                    vectors.append("🟡 MEDIUM: DMARC record yo'q")
            except:
                vectors.append("🟡 MEDIUM: DMARC record yo'q")
                
        except Exception as e:
            vectors.append(f"⚠️ Tahlil xatosi: {str(e)}")
        
        return vectors


def main():
    """Dasturni ishga tushirish"""
    app = QApplication(sys.argv)
    app.setApplicationName("Pentest Recon Tool")
    app.setApplicationVersion("3.1")
    app.setOrganizationName("RedTeam")
    
    window = PentestWhoisGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()