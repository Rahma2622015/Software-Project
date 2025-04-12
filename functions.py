import re

class functions:

    def is_valid_email(self,email: str) -> bool:
        email_regex = r"(^[A-Za-z0-9]+@[A-Za-z0-9]+\.(com|net))"
        return re.match(email_regex, email) is not None

    def sanitize_password(self, input_password):
        suspicious_patterns = ["import", "exec", "eval", "os.", "sys.", "subprocess", "open(", "compile("]
        for pattern in suspicious_patterns:
            # استخدام re.escape لهروب الرموز الخاصة في النمط
            escaped_pattern = re.escape(pattern)
            if re.search(escaped_pattern, input_password, re.IGNORECASE):
                return ""
        return input_password

    def is_strong_password(self, password):
        return (
                len(password) >= 8 and
                re.search(r"[A-Z]", password) and
                re.search(r"[a-z]", password) and
                re.search(r"\d", password) and
                re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
        )


