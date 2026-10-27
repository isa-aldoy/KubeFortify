# KubeFortify
Offline security lint for Kubernetes workload YAML files. Detects privileged containers, host network/PID, mutable images, writable root filesystems and privilege escalation defaults.

## Run
```sh
pip install -r requirements.txt
python kubefortify.py examples/unsafe.yml
python -m unittest discover -s tests -v
```
Returns nonzero when findings exist. Does not connect to Kubernetes or modify deployments. Currently inspects Pod and common workload pod templates; it is not a complete CIS benchmark or Kubernetes posture engine.
