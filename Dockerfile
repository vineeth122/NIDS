FROM python:3.8

ADD src/script1.py /


RUN apt-get update --fix-missing && apt-get -y install gcc && apt -y install libpcap0.8 && apt -y install tcpdump


RUN  pip install scapy

RUN pip install tomlkit && git clone https://github.com/chaimleib/intervaltree.git && cd intervaltree && python3 setup.py install

ENTRYPOINT ["python3","script1.py"]
