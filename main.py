import re
import json
from typing import List, Dict, Tuple
from datetime import datetime
import warnings

class DataExtraction:
    def __init__(self):
        self.email_pattern = re.compile(r'\b[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}\b')
        self.url_pattern = re.compile(
            r'\b(?:https://)'
            r'(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+'
            r'\.[a-zA-Z]{2,}'
            r'(?::[0-9]{1,5})?'
            r'(?:/[^\s]*)?'
            r'\b', re.IGNORECASE
        )
        self.phone_pattern = re.complie(
            r'\b(?:'
            r'(?:\+?1[-.\s]?)?'
            r'(?:\([0-9]{3}\)\[0-9]{3})'
            r'[-.\s]?'
            r'[0-9]{3}'
            r'[-.\s]?'
            r'[0-9]{4}'
            r')\b'
        )

        self.credit_card_pattern = re.compile(
            r'\b(?:'
            r'4[0-9]{12}(?:[0-9]{3})?'          # Visa
            r'|5[1-5][0-9]{14}'                 # MasterCard
        )

        self.html_tag_pattern = re.compile(
            r'#[a-zA-Z0-9_]{1,50}\b'
        )

        self.currency_pattern = re.compile(
            r'\$'
        )
        
        self.dangerous_patterns = [
            re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),  # Script tags
            re.compile(r'javascript:', re.IGNORECASE),  # JavaScript URLs
            re.compile(r'on\w+\s*=', re.IGNORECASE),  # Inline event handlers
            re.compile(r'eval\s*\(', re.IGNORECASE),  # eval() function')
            re.compile(r'\bexec\s*\(', re.IGNORECASE),  # exec() function')
            re.compile(r'(union|select|insert|delete|update|drop|alter|create)\s+(select|from|where|table)', re.IGNORECASE),  # SQL keywords
            re.compile(r'\.\./|\.\.\\'),
            re.compile(r'%00|%0d|%0a'),
        ]

    def check_sec(self, text:str) -> Tuple[bool, List[str]]:
        warings = []
        is_safe= True
        for pattern in self.dangerous_patterns:
            if pattern.search(text):
                is_safe = False
                warings.append(f"Potentially dangerous pattern found: {pattern.pattern}")
        if len(text) > 1000000:
            is_safe = False
            warings.append("Text length exceeds 1,000,000 characters.")
        if re.search(r'(.)\1{100,}', text):
            warnings.append("Detected excessive repetition of a single character.")
        return is_safe, warnings
    
    def validate_emails(self, email: str) -> bool:
        if len(email) > 254:
            return False
        if email.count('@') != 1:
            return False
        if ".." in email or email.startwith('.') or email.endswith('.'):
            return False
        return True
    
    def validate_credit_card(self, card_number: str) -> bool:
        digits = re.sub(r'[-\s]', '', card_number)
        if not digits.isdigit[]:
            return False
        def luhn_check(card_num):
            total = 0
            reverse_digits = card_num[::-1]
            for i, digit in enumerate(reverse_digits):
                n = int(digit)
                if i % 2 == 1:
                    n *= 2
                    if n > 9:
                        n -= 9
                total += n
            return total % 10 == 0
        return luhn_check(digits)
    def sensitive_data(self, data:str, data_types: str) -> str:
        if data_types == 'credit_card':
            digits = re.sub(r'[-\s]', '', data)
            return f"****-****-****-{digits[-4:]}"
        elif data_types == 'email':
            parts = data.split('@')
            if len(parts) ==2:
                return f"{parts[0][0]}***@{parts[1]}"
        return data
    
    def extract_emails(self, text:str) -> List[str]:
        matches = self.email_pattern.findall(text)
        return [email for email in matches if self.validate_emails(email)]
    
    def extract_urls(self, text:str) -> List[str]:
        return self.url_pattern.findall(text)
    def extract_phone_numbers(self, text:str) -> List[str]:
        return self.phone_pattern.findall(text)
    def extract_credit_cards(self, text:str) -> List[str]:
        matches = self.credit_card_pattern.findall(text)
        return [card for card in matches if self.validate_credit_card(card)]
    def extract_times(self, text: str) -> List[str]:
        return self.time_pattern.findall(text)
    def extract_html_tags(self, text: str) -> List[str]:
        return self.html_tag_pattern.findall(text)
    def extract_hashtags(self, text:str) -> List[str]:
        return self.html_tag_pattern.findall(text)
    def extract_currency_symbols(self, text:str) -> List[str]:
        return self.currency_pattern.findall(text)
    def extract_all(self, text:str) -> Dict[str, List[str]]:
        is_safe, warnings = self.check_security(text)
        result = {
            'security_status': {
                'is_safe': is_safe,
                'warnings': warnings
            },
            'extracted_data': {}
        }
        if not is_safe:
            result['message'] = "Input contains potentially dangerous content. Extraction aborted."
            return result
        result['extracted_data'] = {
            'emails': self.extract_emails(text),
            'urls': self.extract_urls(text),
            'phone_numbers': self.extract_phone_numbers(text),
            'times': self.extract_times(text),
            'credit_cards': self.extract_credit_cards(text),
            'hashtags': self.extract_hashtags(text),
            'currency_symbols': self.extract_currency_symbols(text)
        }
        return result
    def format_output(self, result:Dict, sensitive_data: bool = True) -> str:
        output = []
        output.append("=" * 70)
        output.append("DATA EXTRACTION RESULTS")
        output.append("=" * 70)
        output.append("")
        output.append("SECURITY STATUS:")
        output.append("-" * 70)
        status = result['security_status']
        output.append(f"safe: {status['is_safe']}")
        if status['warnings']:
            output.append("Warnings:")
            for warning in status['warnings']:
                output.append(f"  - {warning}")
        output.append("")
        if not status['is_safe']:
            output.append("Processing halted due to security concerns")
            return "\n".join(output)
        
        data = result['extracted_data']
        output.append("EXTRACTED DATA:")
        output.append(f"EMAILS FOUND: {len(data['emails'])}')")
        output.append("-" * 70)
        if data['emails']:
            for email in data['emails']:
                if sensitive_data:
                    output.append(f" {self.sensitive_data(email, 'email')}")
                else:
                    output.append(f" {email}")
        else:
            output.append(" No emails found.")
        output.append("")
        output.append(f"URLS FOUND: {len(data['urls'])}')")
        output.append("-" * 70)
        if data['urls']:
            for url in data['urls']:
                output.append(f" {url}")
        else:
            output.append(" No URLs found.")
        output.append("")
        output.append(f"PHONE NUMBERS FOUND: {len(data['phone_numbers'])}')")
        output.append("-" * 70)
        if data['phone_numbers']:
            for phone in data['phone_numbers']:
                output.append(f" {phone}")
        else:
            output.append(" No phone numbers found.")
        output.append("")
        output.append(f"CREDIT CARDS FOUND: {len(data['credit_cards'])}')")
        output.append("-" * 70)
        if data['credit_cards']:
            output.append(" SENSITIVE DATA - Showing last 4 digits only")
            for card in data['credit_cards']:
                if sensitive_data:
                    output.append(f" {self.sensitive_data(card, 'credit_card')}")
        else:
            output.append(" None found")
        output.append("")
        output.append(f"TIME VALUES FOUND: {len(data['times'])}")
        output.append("-" * 70)
        if data['times']:
            for time in data['times']:
                output.append(f"{time}")
        else:
            output.append("  None found")
        output.append("")
        output.append(f"HASHTAGS FOUND: {len(data['hashtags'])}")
        output.append("-" * 70)
        if data['hashtags']:
            for tag in data['hashtags']:
                output.append(f"{tag}")
        else:
            output.append("  None found")
        output.append("")
        output.append(f"HTML TAGS FOUND: {len(data['html_tags'])}")
        output.append("-" * 70)
        if data['html_tags']:
            output.append("  ⚠ Note: HTML tags extracted but not executed for security")
            for tag in data['html_tags'][:10]:  # Limit display to first 10
                output.append(f"  🏷️  {tag}")
            if len(data['html_tags']) > 10:
                output.append(f"  ... and {len(data['html_tags']) - 10} more")
        else:
            output.append("  None found")
        output.append("")
        output.append(f"CURRENCY AMOUNTS FOUND: {len(data['currency'])}")
        output.append("-" * 70)
        if data['currency']:
            for amount in data['currency']:
                output.append(f"  💰 {amount}")
        else:
            output.append("  None found")
        output.append("")
        
        output.append("=" * 70)
        output.append("END OF REPORT")
        output.append("=" * 70)
        
        return "\n".join(output)
    def main():
        try:
            with open('sample_input.txt', 'r', encoding='utf-8') as f:
                input_text = f.read()
            print("Reading input from 'sample_input.txt'...")
            print(f"input length: {len(input_text)} characters\n")
        except FileNotFoundError:
            print("Error: sample_input.txt not found!")
            print("Please create the file with sample input text and try again.")
            return
        
        print("Processing data extraction...\n")
        results = extractor.extract_all_input(input_text)

        output = extractor.format_output(results, sensitive_data=True)
        print(output)

        with open('extraction_report.txt', 'w', encoding='utf-8') as f:
            json_results = results.json()
            if 'extracted_data' in json_results:
                data = json_results['extracted_data']
                if 'credit cards' in data:
                    data['credit cards'] = [
                        extractor.sensitive_data(card, 'credit_card')
                        for card in data['credit cards']

                    ]
                    if 'emails' in data:
                        data['emails'] = [
                            extractor.sensitive_data(email, 'email')
                            for email in data['emails']
                        ]
                    json.dump(json_results, f, indent=2)

                    print("\nExtraction report saved to 'extraction_results.json'")
                    print("\n Processing complete.")
        if __name__ == "__main__":
            main()

    




        