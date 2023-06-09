# Network Intrusion Detection System

### Specification

This Network Intrusion Detection System processes PCAP Files to detect attack using a signature database provided in TOML format. Each signatures in the file are regular expression over byte strings and are matched against IP datagram payloads and TCP streams.

Following is the structure of the TOML Signature Database file:
```
signatures = [
  "foo",
  "bar[0-9]+",
  "pwned_[a-zA-Z_]+_grade"
]
```
The NIDS features:

- IPv4 and TCP checksum verification failing to which packets are dropped silently
- Custom TCP stream reassembly implementing a *first-received* policy for overlapping segments
- Do not track TCP sessions where initial TCP handshake was not observed
- Bounded memory use during execution to prevent DoS attacks using Buffer Trimming

### Logging Detection

Detections are printed to stdout as individual JSON objects, one per line. 

The format of a single detection is as follows.
```json
{
    "tv_sec": 1600890293,           # Packet timestamp seconds (since UNIX epoch)
    "tv_usec": 0,                   # Packet timestamp microseconds field
    "source": {
        "ipv4_address": "10.0.0.1", # Source IPv4 address
        "tcp_port": 34567           # Source TCP port, or null if N/A
    },
    "target": {
        "ipv4_address": "10.0.0.2", # Target IPv4 address
        "tcp_port": 1234            # Target TCP port, or null if N/A
    },
    "attack": 0                     # Signature index in database (0-indexed)
}
```
Note: The output is pretty printed for explanatorty purpose the actual output will be single lined

### Build and Run

To build and run this project, you need [docker installed](https://docs.docker.com/engine/install/) on your machine.

Once docker is installed, clone the repository, and follow these steps:

1. Build the docker image - `docker build --pull --rm -f "nids/Dockerfile" -t <image_name>:latest "nids"`
2. Run the docker image - `docker run -it -m 256m -v $(pwd):/data <image_name}> /data/<database_filename> /data/<pcap_filename>`
  - `-v $(pwd):/data` : mounts the current working directory to the container as `/data`. `$(pwd)` can be replaced by the directory path where database files and pcap files are stored.
  - `/data/<database_filename>`, `/data/<pcap_filename>` : Path for signature db file and pcap file may vary according to the directory structure maintained.
  - `-m` : sets the memory bound for the docker container
