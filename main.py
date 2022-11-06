# Author:    Nirmal Selvarathinam
# Created:   18.06.2021
# (c) Copyright by Microsoft


def readYAML(urls):
    with open('url_list.yaml') as f:
        data = yaml.load(f, Loader=yaml.FullLoader)
        return data[urls]

def parse_HTTP_response(resp):
    extractor = URLExtract()
    urls = extractor.find_urls(resp)
    return urls


def get_HTTP_response(url):
    resp = req.get(url)
    return resp.text

def check_HSTS(url):
    resp = req.get(url)
    headers = resp.headers
    print("\n\nHeaders set are : \n")
    for k,v in headers.items():
        print(k+" : "+v)

    if("Strict-Transport-Security" in headers.keys()):
        print("\n\nHSTS header present\n")
    else:
        print("\n\nStrict-Transport-Security is missing\n")

def count_HTTP_links(url_list):

    count_https = 0
    count_http = 0
    total_urls = len(url_list)
    http_url_list = []
    https_url_list = []

    for i in range(total_urls):
        temp = url_list[i][0:5]
        if(temp == "https"):
            count_https = count_https + 1
            https_url_list.append(url_list[i])
        elif(temp == "http:"):
            count_http = count_http + 1
            http_url_list.append(url_list[i])

    print("HTTPS URL List: ", https_url_list)
    print("HTTP URL List: ", http_url_list)

    # Calculate Hash
    latest_hash = compute_sha256(https_url_list)
    # Verify Hash for SSL Strip
    check_fingerprint_sslstrip(latest_hash)

    return count_https, count_http


def compute_sha256(url_list):

    temp_str = ""
    for item in url_list:  # Iterating and adding the list element to the str variable
        temp_str += str(item)

    result = hashlib.sha256(temp_str.encode())

    # printing the equivalent hexadecimal value
    print("\nOBSERVATIONS:")
    print("SHA256 fingerprint of HTTPS URL List: ", result.hexdigest())

    return str(result.hexdigest())

def count_HTTPS_links(url):
    return


def check_fingerprint_sslstrip(latest_hash):
    stored_hash_unizg_hr = "c410cd8e08714a2b9c9376ae6d61236e4af4b760757df13f310889b0ee2ead3b"
    if(latest_hash == stored_hash_unizg_hr):
        print("No SSL Stripping action found...")
    else:
        print("MITM Alert: SSL Stripping in progress...")

if __name__ == '__main__':

    #Read yaml for URLs
    url_list_yaml = readYAML('urls')
    for i in range(len(url_list_yaml)):
        print("Target Link - " + url_list_yaml[i])
        resp = get_HTTP_response(url_list_yaml[i])
        urls = parse_HTTP_response(resp)
        #print(urls)
        count_https, count_http = count_HTTP_links(urls)

        print("Total URLs present", count_http + count_https)
        print("https url count: ", count_https)
        print("http url count: ", count_http)
        # check_HSTS(url_list_yaml[i])
