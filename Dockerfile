FROM python:3
RUN mkdir /bot

WORKDIR /bot
RUN apt-get update && apt-get install -y netcat ca-certificates && \
wget https://raw.githubusercontent.com/eficode/wait-for/v2.1.3/wait-for && \
chmod +x wait-for && \
update-ca-certificates --fresh

COPY requirements.txt /bot/requirements.txt
RUN pip install -r /bot/requirements.txt

COPY . /bot

CMD ./wait-for db:3306 -- python3 bot.py
