from urllib.parse import urlparse 

url = input("Enter a URL : ")
is_ip = True
looks_like_ip = True
found_suspicious = False
risk_point = 0
special_count=0

result = urlparse(url)

print("\n URL Analysis  ")
print("URL = ",url)
print("Protocol :", result.scheme)
print("Domain   :", result.netloc)
print("Path     :", result.path)
print("Length   :", len(url))
print("Secure?  :", result.scheme == "https")

security_part = result.path + result.netloc

parts = result.netloc.split(".")

# IP address detection
if len(parts) !=4:
    is_ip = False

for part in parts:
    if not part.isdigit():
        looks_like_ip = False
        is_ip = False
    elif int(part) > 255:
        is_ip = False

if is_ip:
    print("ip address detected")
    risk_point+=30
elif looks_like_ip:
    risk_point+=40
    print("not an ip address")
else:
    print("Normal domain detected")

# suspicious word detection
suspicious = [
    "login",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "bank",
    "signin",
    "password"
]
for word in suspicious:
    if word in url:
        print("Suspicious word:", word)
        found_suspicious = True
        risk_point+=20

if not found_suspicious:
    print("No suspicious words detected")

# long URL detection
if(len(url)>75):
    print("unusual large URL")
    risk_point+=10

#HTTP detection
if result.scheme != "https":
    print("URL is not using HTTPS")
    risk_point+=15

# unusual character @ detection
counter=url.count("@")
if (counter>0) :
    print("suspicious @ detected")
    risk_point+=25

if (len(parts)-2 > 2 ):
    print("Too many subdomains")
    risk_point+=10

special_chars = ["%", "_", "-" ]

for char in special_chars:
    count =  security_part.count(char)
    special_count+=count


if(special_count>4) :
    print("unusual more special cheracter are used")
    risk_point+=20

if url.count("%")>0:
    print("URL contains encoded characters")
    risk_point+=5

if result.netloc.count("-") > 2:
    print("Many hyphens in domain")
    risk_point+=10

print("risk point is ", risk_point)