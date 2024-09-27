#--------------------------------------------------------------------------------------------------
# Copyright (C) 2024 Intel Corporation. All Rights Reserved.
#--------------------------------------------------------------------------------------------------
# This Dockerfile is used to build a TPM simulator image.   It is used for unit testing the go-tpm
# package.
#
# For example... 
# docker run -d --name tpm-simulator -p 2321:2321 -p 2322:2322 tpm-simulator 
# tpm2_startup -c -T mssim:port=2321
# tpm2_pcrread -T mssim:port=2321
# docker rm -f tpm-simulator
#--------------------------------------------------------------------------------------------------
FROM ubuntu:22.04

RUN apt update
RUN apt-get install build-essential libssl-dev wget tpm2-tools -y

RUN mkdir /build
WORKDIR /build
RUN wget https://sourceforge.net/projects/ibmswtpm2/files/ibmtpm1682.tar.gz/download
RUN tar -xvf download 
RUN cd src && make

RUN mkdir /simulator
WORKDIR /simulator
RUN cp /build/src/tpm_server .

EXPOSE 2321
EXPOSE 2322
CMD ["./tpm_server"]