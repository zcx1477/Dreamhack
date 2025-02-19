FROM ubuntu@sha256:daf3e62183e8aa9a56878a685ed26f3af3dd8c08c8fd11ef1c167a1aa9bd66a3

RUN apt update
RUN apt-get install -y socat

COPY ./deploy/flag /flag
COPY ./deploy/santa_coming_to_town /santa_coming_to_town

RUN chmod 755 /flag /santa_coming_to_town

EXPOSE 8080
CMD socat TCP-LISTEN:8080,reuseaddr,fork EXEC:/santa_coming_to_town