# RDump

RDump is a Python 3 app which is inspired by [GoldenEye](https://github.com/jseidl/GoldenEye.git) DOS tool.

The idea of RDump is to expand the capabilities of GoldenEye and also simplify to the author's specific needs. The tool should only be used for security testing purposes only.

RDump is tested on Python 3.8.1, in case you encountered a bug don't hesitate to create a pull request.

## Requirements
* [Python 3.8.1](https://www.python.org/downloads/release/python-381)
* [Package Manager](https://pip.pypa.io/en/stable/)

## Installation
* Create a virtual environment
```bash
python3 -m venv venv
```
* Enable the virtualenvironment
```bash
source venv/bin/activate
```
* Install libraries
```bash
pip install -r requirements.txt
```

## Usage
```bash
rdump.py [-h] -t TARGET [-u USER_AGENT] [-r REFERER] [-w WORKERS] [-x RETRIES] [-a AUTHORIZATION] [-m {GET,POST,PUT,DELETE}] [-d DATA] [-c CONTENT_TYPE] [-v {true,false}]
optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target HTTP URL to be attacked
  -u USER_AGENT, --user-agent USER_AGENT
                        Set a specific useragent to be used in the request
  -r REFERER, --referer REFERER
                        Set a specific useragent to be used in the request
  -w WORKERS, --workers WORKERS
                        Set a specific number of parallel connection
  -x RETRIES, --retries RETRIES
                        Max retries per worker before terminating
  -a AUTHORIZATION, --authorization AUTHORIZATION
                        HTTP Request Authorization (e.g.: 'Bearer <Token>')
  -m {GET,POST,PUT,DELETE}, --method {GET,POST,PUT,DELETE}
                        HTTP Method for the request
  -d DATA, --data DATA  HTTP Body Request - a string json
  -c CONTENT_TYPE, --content-type CONTENT_TYPE
                        Content Type of HTTP Body
  -v {true,false}, --verbose {true,false}
                        Show verbose output
```

## License
This software is distributed under the GNU General Public License version 3 (GPLv3)

## LEGAL NOTICE
THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY! IF YOU ENGAGE IN ANY ILLEGAL ACTIVITY THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT. BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.
