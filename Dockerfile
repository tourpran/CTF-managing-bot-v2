FROM python:3
RUN mkdir /bot

COPY requirements.txt /bot/requirements.txt
RUN pip install -r /bot/requirements.txt
COPY . /bot

WORKDIR /bot

RUN apt-get update && apt-get install -y netcat ca-certificates && \
wget https://raw.githubusercontent.com/eficode/wait-for/v2.1.3/wait-for && \
chmod +x wait-for && \
update-ca-certificates --fresh

# CMD sleep 15; python3 /bot/bot.py
# CMD bash -c "while true; do sleep 2; done"
CMD ./wait-for db:3306 -- python3 bot.py
