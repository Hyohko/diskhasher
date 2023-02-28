FROM phusion/holy-build-box-64:latest
RUN curl https://sh.rustup.rs -sSf > ./rustup-init.sh && \
chmod 755 ./rustup-init.sh && \
./rustup-init.sh -y && \
rm ./rustup-init.sh