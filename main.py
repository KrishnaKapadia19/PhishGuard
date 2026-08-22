from urllib.parse import urlparse, unquote

url = input("Enter a URL : ")


# Normalize URL
def normalize_url(url):
    if "://" not in url:
        url = "http://" + url
    return url


# Count digits
def count_digits(domain):
    digit_count = 0

    for char in domain:
        if char.isdigit():
            digit_count += 1

    return digit_count


# Check IP
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

    return is_ip, looks_like_ip


# Analyze IP
def analyse_ip(is_ip, looks_like_ip):
    if is_ip:
        return "ip"
    elif looks_like_ip:
        return "invalid_ip"
    else:
        return "domain"

# Empty URL
def check_valid_url(domain):
    if domain == "":
        return False
    return True

# Check suspicious words
def check_suspicious_word(domain, path, decoded_domain, decoded_path):
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

    count = 0

    for word in suspicious:
        if word in domain:
            print("Suspicious word in domain:", word)
            count += 1

        elif word in path:
            print("Suspicious word in path:", word)
            count += 1

        elif word in decoded_domain:
            print("Suspicious word in decoded domain:", word)
            count += 1

        elif word in decoded_path:
            print("Suspicious word in decoded path:", word)
            count += 1

    return count


# Check URL length
def check_url_length(url):
    if len(url) > 75:
        print("Unusual large URL")
        return True
    return False


# Check HTTPS
def check_https(scheme):
    if scheme != "https":
        print("URL is not using HTTPS")
        return True
    return False


# Check @
def check_at_symbol(url):
    if url.count("@") > 0:
        print("Suspicious @ detected")
        return True
    return False


# Check domain length
def check_domain_length(domain):
    if len(domain) > 30:
        print("Long domain detected")
        return True
    return False


# Check subdomains
def check_subdomain(domain):
    parts = domain.split(".")

    if len(parts) - 2 > 2:
        print("Too many subdomains")
        return True

    return False


# Count special characters
def count_special_characters(security):
    special_chars = ["%", "_", "-"]
    special_count = 0

    for char in special_chars:
        special_count += security.count(char)

    return special_count


# Check special characters
def check_special_character_count(special_count):
    if special_count > 4:
        print("Unusual more special characters are used")
        return True

    return False


# Check encoding
def check_url_encoding(url):
    if url.count("%") > 0:
        print("URL contains encoded characters")
        return True

    return False


# Check hyphens
def check_hyphen(domain):
    if domain.count("-") > 2:
        print("Many hyphens in domain")
        return True

    return False


# Check digits
def check_digit_count(domain):
    digit_count = count_digits(domain)

    print("Digit count in domain:", digit_count)

    if digit_count > 5:
        print("Too many digits in domain")
        return True

    return False

# Check risk
def check_risk_level(risk_point):
    if risk_point >= 60:
        return "High risk"
    elif risk_point >= 30:
        return "Medium risk"
    else :
        return "Low risk"

# Decode URL
def decode_url(url):
    return unquote(url)

# Analyze URL
def analyze_url(url,result):
    decoded_url = decode_url(url)
    decoded_result = urlparse(decoded_url)

    security_part = result.path + result.netloc

    decoded_domain = decoded_result.netloc
    decoded_path = decoded_result.path

    risk_point = 0
    # URL information
    print("\nURL Analysis")
    print("URL =", url)
    print("Protocol :", result.scheme)
    print("Domain   :", result.netloc)
    print("Path     :", result.path)
    print("Length   :", len(url))
    print("Secure?  :", result.scheme == "https")


    # IP detection
    is_ip, looks_like_ip = check_ip(result.netloc)

    ip_type = analyse_ip(is_ip, looks_like_ip)

    if ip_type == "ip":
        print("IP address detected")
        risk_point += 30

    elif ip_type == "invalid_ip":
        print("Not a valid IP address")
        risk_point += 40

    else:
        print("Normal domain")



    # Suspicious words
    found_suspicious = check_suspicious_word(
        result.netloc, result.path, decoded_domain, decoded_path
    )

    risk_point += found_suspicious * 10


    # URL length
    if check_url_length(url):
        risk_point += 10


    # HTTPS
    if check_https(result.scheme):
        risk_point += 15


    # @ symbol
    if check_at_symbol(url):
        risk_point += 25

    # Domain length
    if check_domain_length(result.netloc):
        risk_point += 10

    # Subdomains
    if check_subdomain(result.netloc):
        risk_point += 10


    # Special characters
    special_count = count_special_characters(security_part)

    if check_special_character_count(special_count):
        risk_point += 20


    # URL encoding
    if check_url_encoding(url):
        risk_point += 5


    # Hyphens
    if check_hyphen(result.netloc):
        risk_point += 10


    # Digits
    if check_digit_count(result.netloc):
        risk_point += 10


    # Final score
    risk_level = check_risk_level(risk_point)

    print("Risk point is : ", risk_point)
    print("Risk level is : ", risk_level)

# Prepare URL
url = normalize_url(url)

result = urlparse(url)




#Invalid URL
if not check_valid_url(result.netloc):
    print("Invalid URL")
else:
    analyze_url(url,result)