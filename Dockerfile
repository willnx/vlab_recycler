FROM willnx/vlab-base

RUN mkdir /etc/vlab
COPY  dist/*.whl /tmp
RUN pip3 install /tmp/*.whl && rm /tmp/*.whl
RUN apk del gcc

WORKDIR /usr/lib/python3.6/site-packages/recycler
CMD ["python3", "recycle.py"]
