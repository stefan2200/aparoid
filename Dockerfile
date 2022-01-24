FROM ubuntu:20.04

LABEL \
    name="Aparoid" \
    author="stefan2200 <stefan@stefanvlems.nl>" \
    maintainer="Stefan Vlems <stefan@stefanvlems.nl>"

ENV DEBIAN_FRONTEND="noninteractive"

RUN apt update -y && apt install -y  --no-install-recommends \
    python3 \
    python3-pip \
    locales \
    sqlite3 \
    default-jre \
    android-tools-adb \
    gunicorn \
    libmagic1

RUN locale-gen en_US.UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

RUN mkdir /app
WORKDIR /app

RUN apt clean && apt autoclean && apt autoremove -y

COPY . .
RUN chmod +x setup.sh start.sh
RUN ./setup.sh docker
ARG CONTAINERCONFIG
RUN if [ "$CONTAINERCONFIG" = "enabled" ]; \
        then cp config_container.py config.py; \
    fi


EXPOSE 7300 7300 5037 5037
CMD ["/app/start.sh"]