FROM python:3

WORKDIR /usr/src/app

# Install openconnect
RUN apt-get update && apt-get install -y --no-install-recommends \
    openconnect \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Setup python requirements
COPY ./requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Setup script
COPY ./main.py ./

# Setup wrapper script
ENTRYPOINT [ "python", "-u", "/usr/src/app/main.py" ]
