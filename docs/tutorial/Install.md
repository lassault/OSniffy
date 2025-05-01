First, we need to install MySQL and Grafana on the computer.

Second, we should create a virtual env to install all the dependencies:
`python3 -m venv venv`

Now, let's activate it:
`source venv/bin/activate`

To ensure that all the libraries can be installed, we must install this two extra packages:
`sudo apt-get install libpcap-dev # for python-libpcap`
`sudo apt-get install python3-dev # for python-libpcap`

# Reference 1: https://python-libpcap.readthedocs.io/en/latest/#install
# Reference 2: https://stackoverflow.com/questions/21530577/fatal-error-python-h-no-such-file-or-directory

And now, install the dependencies:
`python -m pip install -r requirements.txt`
