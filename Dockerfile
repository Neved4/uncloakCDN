FROM ubuntu:latest
RUN apt-get update -y
RUN apt-get install -y curl dnsutils jq libxml2-utils whois
WORKDIR /app
COPY src/uncloakCDN.sh /app
RUN chmod +x ./uncloakCDN.sh
CMD ["./uncloakCDN.sh"]
