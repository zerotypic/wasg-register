FROM python:3
RUN pip3 install pycryptodome requests
COPY wasg-register.py /
ENTRYPOINT ["python3", "wasg-register.py"]
