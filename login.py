#!/usr/bin/env python3
import time
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import http.client
import json
import urllib
import ssl
from urllib.parse import urlencode, quote_plus

def print_json(j, prefix=''):
    for key, value in j.items():
        if isinstance(value, dict):
            print('%s%s' % (prefix, key))
            print_json(value, prefix + '  ')
        else:
            print('%s%s:%s' % (prefix, key, value))

USERNAME = 'danielthulin'
PASSWORD = ''
SERVICE = 'NEXTAPI'
URL = 'api.test.nordnet.se'
API_VERSION = '2'

def get_hash(username, password):
    timestamp = int(round(time.time() * 1000))
    timestamp = str(timestamp).encode('ascii')

    username_b64 = base64.b64encode(username.encode('ascii'))
    password_b64 = base64.b64encode(password.encode('ascii'))
    timestamp_b64 = base64.b64encode(timestamp)

    auth_val = username_b64 + b':' + password_b64 + b':' + timestamp_b64
    rsa_key = RSA.importKey(open('NEXTAPI_TEST_public.pem').read())
    cipher_rsa = PKCS1_v1_5.new(rsa_key)
    encrypted_hash = cipher_rsa.encrypt(auth_val)
    encoded_hash = base64.b64encode(encrypted_hash)

    print(auth_val, encoded_hash)
    return encoded_hash

def main():
    auth_hash = get_hash(USERNAME, PASSWORD)

    headers = {"Accept": "application/json"}
    conn = http.client.HTTPSConnection(URL)

    # GET server status
    conn.request('GET', '/next/' + API_VERSION + '/', '', headers)
    r = conn.getresponse()
    response = r.read().decode('utf-8')
    j = json.loads(response)
    print_json(j)

    # POST login
    params = urlencode({'service': 'NEXTAPI', 'auth': auth_hash})
    conn.request('POST', '/next/' + API_VERSION + '/login', params, headers)
    r_log = conn.getresponse()
    response_log = r_log.read().decode('utf-8')
    j = json.loads(response_log)
    print_json(j)

    #sarar session_key som username:password
    session_key = j['session_key'] + ':' + j['session_key']

    print('------------------------------------------------------------------------')
    print('Account request')
    print('------------------------------------------------------------------------')


    acc_conn = http.client.HTTPSConnection(URL)

    #session_key = j['session_key'] + ':' + j['session_key']
    b64_auth = base64.b64encode(bytes(session_key, encoding='utf-8')).decode("utf-8")
    acc_headers = {"Accept": "application/json",'Accept-Language':'sv'}
    acc_headers['Authorization'] = 'Basic ' + b64_auth

    acc_params = urlencode({'Accept-Language':'sv', 'auth': {session_key}})
    acc_conn.request('GET', '/next/' + API_VERSION + '/accounts', acc_params, acc_headers)
    r_acc = acc_conn.getresponse()
    response_acc = r_acc.read().decode('utf-8')
    j_acc = json.loads(response_acc)
    print(j_acc)

    print('------------------------------------------------------------------------')
    print('Account info')
    print('------------------------------------------------------------------------')


    #sparar kontonummer i accno
    accno = j_acc[0]['accno']

    # GET information från valt account
    order_conn = http.client.HTTPSConnection(URL)

    b64_auth = base64.b64encode(bytes(session_key, encoding='utf-8')).decode("utf-8")
    order_headers = {"Accept": "application/json",'Accept-Language':'sv'}
    order_headers['Authorization'] = 'Basic ' + b64_auth
    order_params = urlencode({'Accept-Language':'sv', 'auth': {session_key}})

    order_conn.request('GET', '/next/' + API_VERSION + '/accounts/' + str(accno), order_params, order_headers)
    response_order = order_conn.getresponse()
    r_order = response_order.read().decode('utf-8')
    j_order = json.loads(r_order)
    print(j_order)

    print('------------------------------------------------------------------------')
    print('Market tradables')
    print('------------------------------------------------------------------------')

    # GET market tradables
    markets_conn = http.client.HTTPSConnection(URL)

    b64_auth = base64.b64encode(bytes(session_key, encoding='utf-8')).decode("utf-8")
    markets_headers = {"Accept": "application/json",'Accept-Language':'sv'}
    markets_headers['Authorization'] = 'Basic ' + b64_auth
    markets_params = urlencode({'Accept-Language':'sv', 'auth': {session_key}})

    markets_conn.request('GET', '/next/' + API_VERSION + '/markets', order_params, order_headers)
    response_markets = markets_conn.getresponse()
    r_markets = response_markets.read().decode('utf-8')
    j_markets = json.loads(r_markets)

    #sparar de svenska börslistorna i se_market_list
    se_market_list = []
    for n in range (1, len(j_markets)):
        if j_markets[n]['country'] == 'SE':
            se_market_list.append(j_markets[n])

    print('------------------------------------------------------------------------')
    print('Get lists')
    print('------------------------------------------------------------------------')

    # GET Lists
    li_conn = http.client.HTTPSConnection(URL)

    b64_auth = base64.b64encode(bytes(session_key, encoding='utf-8')).decode("utf-8")
    li_headers = {"Accept": "application/json",'Accept-Language':'sv'}
    li_headers['Authorization'] = 'Basic ' + b64_auth
    li_params = urlencode({'Accept-Language':'sv', 'auth': {session_key}})

    lis = '11'
    li_conn.request('GET', '/next/' + API_VERSION + '/lists', order_params, order_headers)
    response_li = li_conn.getresponse()
    r_li = response_li.read().decode('utf-8')
    j_li = json.loads(r_li)

    se_instru_list = []
    for n in range (0, len(j_li)):
        print(j_li[n])

    print('------------------------------------------------------------------------')
    print('Get instrument lists')
    print('------------------------------------------------------------------------')

    # GET Lists
    ins_li_conn = http.client.HTTPSConnection(URL)

    b64_auth = base64.b64encode(bytes(session_key, encoding='utf-8')).decode("utf-8")
    ins_li_headers = {"Accept": "application/json",'Accept-Language':'sv'}
    ins_li_headers['Authorization'] = 'Basic ' + b64_auth
    ins_li_params = urlencode({'Accept-Language':'sv', 'auth': {session_key}})

    ins_lis = '16314711'
    ins_li_conn.request('GET', '/next/' + API_VERSION + '/lists' + ins_lis, order_params, order_headers)
    response_ins_li = ins_li_conn.getresponse()
    r_ins_li = response_ins_li.read().decode('utf-8')
    j_ins_li = json.loads(r_ins_li)
    print(j_ins_li)
# funkar inte att visa aktierna som finns i listorna....
    '''se_instru_list = []
    for n in range (0, len(j_li)):
        print(j_li[n])'''


'''
    print('------------------------------------------------------------------------')
    print('Tradables intraday')
    print('------------------------------------------------------------------------')

    # GET  tradables intraday
    ti_conn = http.client.HTTPSConnection(URL)

    b64_auth = base64.b64encode(bytes(session_key, encoding='utf-8')).decode("utf-8")
    ti_headers = {"Accept": "application/json",'Accept-Language':'sv'}
    ti_headers['Authorization'] = 'Basic ' + b64_auth
    ti_params = urlencode({'Accept-Language':'sv', 'auth': {session_key}})

    tradable = '11:101'
    ti_conn.request('GET', '/next/' + API_VERSION + '/tradables/intraday/' + tradable, order_params, order_headers)
    response_ti = ti_conn.getresponse()
    r_ti = response_ti.read().decode('utf-8')
    j_ti = json.loads(r_ti)
    print(j_ti)
'''

if __name__ == "__main__":
    main()
