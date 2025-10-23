#!/usr/bin/env python3
"""
Multi-Platform IOC Reputation Checker
Description: Checks IOCs against VirusTotal, AbuseIPDB, AlienVault OTX, and ThreatFox
Author: Security Engineer
Date: 2024
"""

import requests
import json
import time
import csv
import argparse
from datetime import datetime
import os
import sys
import re

# Configuration - ADD YOUR API KEYS HERE
CONFIG = {
    'virustotal': {
        'api_key': 'YOUR_VIRUSTOTAL_API_KEY',
        'base_url': 'https://www.virustotal.com/api/v3'
    },
    'abuseipdb': {
        'api_key': 'YOUR_ABUSEIPDB_API_KEY',
        'base_url': 'https://api.abuseipdb.com/api/v2'
    },
    'alienvault_otx': {
        'api_key': 'YOUR_OTX_API_KEY',
        'base_url': 'https://otx.alienvault.com/api/v1'
    },
    'threatfox': {
        'api_key': '',
        'base_url': 'https://threatfox-api.abuse.ch/api/v1'
    }
}

class IOCReputationChecker:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'IOC-Reputation-Checker/1.0'})

    def looks_like_ip(self, ioc):
        """Check if the IOC looks like an IP address"""
        # IPv4 pattern
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ipv4_pattern, ioc):
            parts = ioc.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return True
        
        # Basic IPv6 pattern (simplified)
        if ':' in ioc and ioc.count(':') >= 2:
            return True
            
        return False

    def is_likely_domain(self, ioc):
        """
        Comprehensive domain detection that handles any TLD
        """
        # Remove common protocol prefixes if present
        ioc = ioc.lower().strip()
        if ioc.startswith(('http://', 'https://', 'ftp://')):
            ioc = ioc.split('://', 1)[1]
        
        # Remove path and query parameters
        ioc = ioc.split('/')[0]
        ioc = ioc.split('?')[0]
        
        # Domain should not contain spaces, slashes, or @ symbols
        if any(char in ioc for char in [' ', '/', '@']):
            return False
        
        # Must contain at least one dot and have at least 2 parts
        if '.' not in ioc:
            return False
        
        parts = ioc.split('.')
        if len(parts) < 2:
            return False
        
        # Last part (TLD) should be between 2 and 24 characters
        # and contain only letters (or hyphens for international TLDs)
        tld = parts[-1]
        if not (2 <= len(tld) <= 24):
            return False
        
        # TLD should be primarily alphabetic (allowing hyphens for IDN)
        if not all(c.isalpha() or c == '-' for c in tld):
            return False
        
        # Each part should not be empty and should not start/end with hyphen
        for part in parts:
            if not part:  # Empty part (like "example..com")
                return False
            if part.startswith('-') or part.endswith('-'):
                return False
            if not all(c.isalnum() or c == '-' for c in part):
                return False
        
        # Additional checks for common domain patterns
        # Domain should not be an IP address
        if self.looks_like_ip(ioc):
            return False
        
        return True
    

        
    def detect_ioc_type(self, ioc):
        """Detect the type of IOC"""
        ioc = ioc.strip().lower()
        
        # Hash detection
        if len(ioc) == 32 and all(c in '0123456789abcdef' for c in ioc):
            return 'md5'
        elif len(ioc) == 40 and all(c in '0123456789abcdef' for c in ioc):
            return 'sha1'
        elif len(ioc) == 64 and all(c in '0123456789abcdef' for c in ioc):
            return 'sha256'
        
        # IP address detection
        elif self.looks_like_ip(ioc):
            return 'ipv4'
        
        # Enhanced Domain detection
        elif self.is_likely_domain(ioc):
            return 'domain'
        
        else:
            return 'unknown'
        
    def check_virustotal(self, ioc, ioc_type):
        """Check IOC against VirusTotal"""
        if not CONFIG['virustotal']['api_key'] or CONFIG['virustotal']['api_key'] == 'YOUR_VIRUSTOTAL_API_KEY':
            return {'error': 'VirusTotal API key not configured'}
        
        headers = {
            'x-apikey': CONFIG['virustotal']['api_key']
        }
        
        try:
            if ioc_type in ['md5', 'sha1', 'sha256']:
                url = f"{CONFIG['virustotal']['base_url']}/files/{ioc}"
            elif ioc_type == 'ipv4':
                url = f"{CONFIG['virustotal']['base_url']}/ip_addresses/{ioc}"
            elif ioc_type == 'domain':
                url = f"{CONFIG['virustotal']['base_url']}/domains/{ioc}"
            else:
                return {'error': f'Unsupported IOC type for VirusTotal: {ioc_type}'}
            
            response = self.session.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                result = {
                    'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                    'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                    'undetected': attributes.get('last_analysis_stats', {}).get('undetected', 0),
                    'harmless': attributes.get('last_analysis_stats', {}).get('harmless', 0),
                    'reputation': attributes.get('reputation', 0),
                    'total_engines': sum(attributes.get('last_analysis_stats', {}).values())
                }
                
                # Calculate threat score
                total_detections = result['malicious'] + result['suspicious']
                if result['total_engines'] > 0:
                    result['threat_score'] = round((total_detections / result['total_engines']) * 100, 2)
                else:
                    result['threat_score'] = 0
                    
                return result
            elif response.status_code == 404:
                return {'error': 'IOC not found in VirusTotal'}
            else:
                return {'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'VirusTotal check failed: {str(e)}'}
    
    def check_abuseipdb(self, ioc, ioc_type):
        """Check IP against AbuseIPDB"""
        if ioc_type != 'ipv4':
            return {'error': 'AbuseIPDB only supports IPv4'}
            
        if not CONFIG['abuseipdb']['api_key'] or CONFIG['abuseipdb']['api_key'] == 'YOUR_ABUSEIPDB_API_KEY':
            return {'error': 'AbuseIPDB API key not configured'}
        
        headers = {
            'Key': CONFIG['abuseipdb']['api_key'],
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': ioc,
            'maxAgeInDays': 90
        }
        
        try:
            url = f"{CONFIG['abuseipdb']['base_url']}/check"
            response = self.session.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                result_data = data.get('data', {})
                
                return {
                    'abuse_confidence_score': result_data.get('abuseConfidenceScore', 0),
                    'total_reports': result_data.get('totalReports', 0),
                    'country_code': result_data.get('countryCode', 'Unknown'),
                    'isp': result_data.get('isp', 'Unknown'),
                    'domain': result_data.get('domain', 'Unknown'),
                    'is_whitelisted': result_data.get('isWhitelisted', False),
                    'last_reported': result_data.get('lastReportedAt', 'Never')
                }
            else:
                return {'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'AbuseIPDB check failed: {str(e)}'}
    
    def check_alienvault_otx(self, ioc, ioc_type):
        """Check IOC against AlienVault OTX"""
        try:
            if ioc_type in ['md5', 'sha1', 'sha256']:
                url = f"{CONFIG['alienvault_otx']['base_url']}/indicators/file/{ioc}/general"
            elif ioc_type == 'ipv4':
                url = f"{CONFIG['alienvault_otx']['base_url']}/indicators/IPv4/{ioc}/general"
            elif ioc_type == 'domain':
                url = f"{CONFIG['alienvault_otx']['base_url']}/indicators/domain/{ioc}/general"
            else:
                return {'error': f'Unsupported IOC type for OTX: {ioc_type}'}
            
            response = self.session.get(url)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract pulse information
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                pulses = data.get('pulse_info', {}).get('pulses', [])
                
                # Get reputation from AlienVault
                reputation = data.get('reputation', 0)
                
                # Extract related malware families
                malware_families = []
                for pulse in pulses[:5]:  # Get first 5 malware families
                    if 'malware_families' in pulse:
                        malware_families.extend(pulse['malware_families'])
                
                return {
                    'pulse_count': pulse_count,
                    'reputation': reputation,
                    'malware_families': list(set(malware_families))[:5],  # Unique families, max 5
                    'is_malicious': reputation is None or reputation < 0  # OTX reputation < 0 means malicious
                }
            elif response.status_code == 404:
                return {'error': 'IOC not found in AlienVault OTX'}
            else:
                return {'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'AlienVault OTX check failed: {str(e)}'}
    
    def check_threatfox(self, ioc, ioc_type):
        """Check IOC against ThreatFox"""
        try:
            # ThreatFox API expects JSON payload
            payload = {
                "query": "search_ioc",
                "search_term": ioc
            }
            
            response = self.session.post(
                CONFIG['threatfox']['base_url'],
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('query_status') == 'ok':
                    results = data.get('data', [])
                    if results:
                        result = results[0]  # Take first result
                        return {
                            'threatfox_id': result.get('id'),
                            'ioc': result.get('ioc'),
                            'threat_type': result.get('threat_type'),
                            'malware': result.get('malware'),
                            'confidence_level': result.get('confidence_level'),
                            'first_seen': result.get('first_seen'),
                            'tags': result.get('tags', [])
                        }
                    else:
                        return {'status': 'not_found'}
                else:
                    return {'error': f"Query failed: {data.get('query_status')}"}
            else:
                return {'error': f'API error: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'ThreatFox check failed: {str(e)}'}
    
    def generate_reputation_report(self, iocs, output_file='ioc_reputation_report.csv'):
        """Generate a comprehensive CSV report"""
        headers = [
            'IOC', 'Type', 'VirusTotal_Threat_Score', 'VirusTotal_Malicious', 
            'VirusTotal_Suspicious', 'VirusTotal_Total_Engines', 'AbuseIPDB_Confidence_Score',
            'AbuseIPDB_Total_Reports', 'OTX_Pulse_Count', 'OTX_Reputation',
            'ThreatFox_Status', 'Overall_Risk', 'Recommendation'
        ]
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            
            for ioc in iocs:
                ioc_type = self.detect_ioc_type(ioc)
                print(f"Checking {ioc} ({ioc_type})...")
                
                # Check all platforms
                vt_result = self.check_virustotal(ioc, ioc_type)
                abuse_result = self.check_abuseipdb(ioc, ioc_type) if ioc_type == 'ipv4' else {}
                otx_result = self.check_alienvault_otx(ioc, ioc_type)
                tf_result = self.check_threatfox(ioc, ioc_type)
                
                # Calculate overall risk
                risk_score = 0
                risk_factors = []
                
                # VirusTotal risk
                if 'threat_score' in vt_result:
                    risk_score += vt_result['threat_score'] / 100
                    risk_factors.append(f"VT:{vt_result['threat_score']}%")
                
                # AbuseIPDB risk
                if 'abuse_confidence_score' in abuse_result:
                    risk_score += abuse_result['abuse_confidence_score'] / 100
                    risk_factors.append(f"Abuse:{abuse_result['abuse_confidence_score']}%")
                
                # OTX risk
                if 'pulse_count' in otx_result:
                    pulse_risk = min(otx_result['pulse_count'] / 10, 1)  # Normalize pulse count
                    risk_score += pulse_risk
                    risk_factors.append(f"OTX:{otx_result['pulse_count']}pulses")
                
                # Determine overall risk level
                if risk_score >= 2:
                    overall_risk = "HIGH"
                    recommendation = "BLOCK"
                elif risk_score >= 1:
                    overall_risk = "MEDIUM"
                    recommendation = "MONITOR/INVESTIGATE"
                else:
                    overall_risk = "LOW"
                    recommendation = "ALLOW"
                
                # Write row to CSV
                row = [
                    ioc,
                    ioc_type,
                    vt_result.get('threat_score', 'N/A'),
                    vt_result.get('malicious', 'N/A'),
                    vt_result.get('suspicious', 'N/A'),
                    vt_result.get('total_engines', 'N/A'),
                    abuse_result.get('abuse_confidence_score', 'N/A'),
                    abuse_result.get('total_reports', 'N/A'),
                    otx_result.get('pulse_count', 'N/A'),
                    otx_result.get('reputation', 'N/A'),
                    'MALICIOUS' if tf_result and 'threat_type' in tf_result else 'CLEAN',
                    overall_risk,
                    recommendation
                ]
                writer.writerow(row)
                
                # Be nice to the APIs
                time.sleep(1)
        
        print(f"\nReport generated: {output_file}")
    
    def check_single_ioc(self, ioc):
        """Check a single IOC and print detailed results"""
        ioc_type = self.detect_ioc_type(ioc)
        print(f"\n{'='*60}")
        print(f"Checking: {ioc} (Type: {ioc_type})")
        print(f"{'='*60}")
        
        results = {
            'VirusTotal': self.check_virustotal(ioc, ioc_type),
            'AbuseIPDB': self.check_abuseipdb(ioc, ioc_type) if ioc_type == 'ipv4' else {'error': 'Only supports IPs'},
            'AlienVault OTX': self.check_alienvault_otx(ioc, ioc_type),
            'ThreatFox': self.check_threatfox(ioc, ioc_type)
        }
        
        for platform, result in results.items():
            print(f"\n{platform}:")
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                for key, value in result.items():
                    print(f"  {key}: {value}")
        
        return results

def main():
    parser = argparse.ArgumentParser(description='IOC Reputation Checker')
    parser.add_argument('--ioc', type=str, help='Check a single IOC')
    parser.add_argument('--file', type=str, help='Check IOCs from a file (one per line)')
    parser.add_argument('--output', type=str, default='ioc_reputation_report.csv', help='Output CSV file name')
    
    args = parser.parse_args()
    
    checker = IOCReputationChecker()
    
    # Check if any API keys are configured
    if CONFIG['virustotal']['api_key'] == 'YOUR_VIRUSTOTAL_API_KEY':
        print("Warning: VirusTotal API key not configured")
    if CONFIG['abuseipdb']['api_key'] == 'YOUR_ABUSEIPDB_API_KEY':
        print("Warning: AbuseIPDB API key not configured")
    
    if args.ioc:
        # Single IOC check
        checker.check_single_ioc(args.ioc)
    elif args.file:
        # Bulk check from file
        try:
            with open(args.file, 'r') as f:
                iocs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            print(f"Loaded {len(iocs)} IOCs from {args.file}")
            checker.generate_reputation_report(iocs, args.output)
            
        except FileNotFoundError:
            print(f"Error: File {args.file} not found")
    else:
        print("Please provide either --ioc for single check or --file for bulk check")
        print("Example: python ioc_reputation_checker.py --file iocs.txt")
        print("Example: python ioc_reputation_checker.py --ioc '8.8.8.8'")

if __name__ == "__main__":
    main()
