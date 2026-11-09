FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    python3 \
    pkg-config \
    libimobiledevice-dev \
    libplist-dev \
    libusbmuxd-dev \
    socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --shell /usr/sbin/nologin ctf

WORKDIR /challenge
COPY client.c .

RUN gcc -g -O0 -o client client.c \
    $(pkg-config --cflags --libs libimobiledevice-1.0) \
    -lpthread \
    && rm client.c

COPY flag.txt /flag.txt
RUN chown ctf:ctf /flag.txt && chmod 0600 /flag.txt

COPY entrypoint.sh /challenge/entrypoint.sh
COPY handler.sh /challenge/handler.sh
RUN sed -i 's/\r$//' /challenge/entrypoint.sh /challenge/handler.sh \
    && chmod +x /challenge/entrypoint.sh /challenge/handler.sh

USER ctf
EXPOSE 1337
CMD ["/challenge/entrypoint.sh"]
