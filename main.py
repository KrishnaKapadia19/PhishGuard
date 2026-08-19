from urllib.parse import urlparse, unquote

url = input("Enter a URL : ")


# URL normalization
def normaliz_url(url):
    if "://" not in url:
        url = "http://" + url
    return url

url = normaliz_url(url)
# Count digits in domain
def count_digits(domain):
    digit_count = 0
    for char in domain:
        if char.isdigit():
            digit_count += 1
    return digit_count


# IP address detection
def check_ip(domain):
    is_ip = True
    looks_like_ip = True
    parts = domain.split(".")
    if len(parts) != 4:
        is_ip = False

    for part in parts:
        if not part.isdigit():
            looks_like_ip = False
            is_ip = False
        elif int(part) > 255:
            is_ip = False
    return is_ip, looks_like_ip, parts


# Suspicious word detection
def check_suspicious_word(url, decoded_url):
    suspicious = [
        "login",
        "verify",
        "verification",
        "account",
        "secure",
        "update",
        "bank",
        "signin",
        "password",
    ]
    found_suspicious = False

    for word in suspicious:
        if word in url or word in decoded_url:
            print("Suspicious word:", word)
            found_suspicious = True
    return found_suspicious

# Long URL detection
def check_url_length(url):
    if len(url) > 75:
        print("unusual large URL")
        return True
    return False

# Domain length detection
def check_domain_length(domain):
    if len(domain) >30:
        print("Long domain detected")
        return True
    return False

# HTTPS detection
def check_https(scheme):
    if scheme != "https":
        print("URL is not using HTTPS")
        return True
    return False

# @ symbol detection
def check_at_symbol(url):
    counter = url.count("@")

    if counter > 0:
        print("suspicious @ detected")
        return True
    return False

risk_point = 0
special_count = 0

result = urlparse(url)
security_part = result.path + result.netloc
decoded_url = unquote(url)

print("\n URL Analysis  ")
print("URL = ", url)
print("Protocol :", result.scheme)
print("Domain   :", result.netloc)
print("Path     :", result.path)
print("Length   :", len(url))
print("Secure?  :", result.scheme == "https")

# IP detection
is_ip, looks_like_ip, parts = check_ip(result.netloc)

# suspicious word detection
found_suspicious = check_suspicious_word(url, decoded_url)
if found_suspicious:
    risk_point += 20

# Long URL detection
if check_url_length(url):
    risk_point+=10


# HTTPS detection
if check_https(result.scheme):
    risk_point+=15


# @ symbol detection
if check_at_symbol(url):
    risk_point+=25


# Subdomain detection
if len(parts) - 2 > 2:
    print("Too many subdomains")
    risk_point += 10


# Special character detection
special_chars = ["%", "_", "-"]

for char in special_chars:
    count = security_part.count(char)
    special_count += count

if special_count > 4:
    print("unusual more special characters are used")
    risk_point += 20


# URL encoding detection
if url.count("%") > 0:
    print("URL contains encoded characters")
    risk_point += 5


# Hyphen detection
if result.netloc.count("-") > 2:
    print("Many hyphens in domain")
    risk_point += 10


# Original and decoded URL
print("Original Url : ", url)
print("Decoded Url : ", decoded_url)


# Domain length detection
if check_domain_length(result.netloc):
    risk_point+=10


# Digit detection
digit_count = count_digits(result.netloc)

print("Digit count in domain:", digit_count)

if digit_count > 5:
    print("Too many digits in domain")
    risk_point += 10


# Final risk score
print("risk point is ", risk_point)
