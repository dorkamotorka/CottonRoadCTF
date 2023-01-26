FROM registry.w0y.at/courses/ws22-attacks-and-defenses-in-computer-security/info/basechecker:1.0

RUN mkdir -p /checker
WORKDIR /checker

COPY requirements.txt /checker/requirements.txt
RUN pip install -r requirements.txt
 
COPY testimage.jpg /checker/testimage.jpg
COPY checker.py /checker/checker.py
USER ctf-checkermaster
ENV CTF_CHECKERSCRIPT /checker/checker.py
ENV CTF_SERVICE cottonroad_checker2
