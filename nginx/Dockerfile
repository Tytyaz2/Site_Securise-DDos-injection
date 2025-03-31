FROM nginx:1.25-alpine

LABEL maintainer="your-team@example.com"

# Install dependencies
RUN apk add --no-cache git build-base linux-headers \
    libxml2-dev libxslt-dev geoip-dev pcre-dev zlib-dev \
    curl openssl-dev yajl-dev libmaxminddb-dev

# Build ModSecurity (v3)
WORKDIR /opt
RUN git clone --depth 1 -b v3.0.8 https://github.com/SpiderLabs/ModSecurity && \
    cd ModSecurity && \
    git submodule init && \
    git submodule update && \
    ./build.sh && ./configure && make && make install

# Build ModSecurity-nginx connector
RUN git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git

# Download and extract nginx source
ENV NGINX_VERSION=1.25.3
RUN curl -sSL https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz | tar -xz && \
    cd nginx-$NGINX_VERSION && \
    ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx && \
    make modules && \
    cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules

# Copy configs
COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity.conf

# Enable the dynamic module
RUN echo "load_module modules/ngx_http_modsecurity_module.so;" > /etc/nginx/modules.conf

# Entrypoint
CMD ["nginx", "-g", "daemon off;"]
