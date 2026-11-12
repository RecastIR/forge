FROM debian:bookworm-20250224-slim@sha256:ceac69add95cb9ac0d99d9569350cc36838b76397d986e1ccc284bd034b58a9f

# apt checks the signed Release and package hashes; the archived Release has expired.
RUN rm /etc/apt/sources.list.d/debian.sources \
    && echo 'deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://snapshot.debian.org/archive/debian/20250224T000000Z bookworm main' > /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=3 update \
    && apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
        gcc-mingw-w64-x86-64-win32=12.2.0-14+25.2 \
        g++-mingw-w64-x86-64-win32=12.2.0-14+25.2 \
        mingw-w64-x86-64-dev=10.0.0-3 \
        binutils-mingw-w64-x86-64=2.40-2+10.4 \
        cmake=3.25.1-1 ninja-build=1.11.1-2~deb12u1 python3=3.11.2-1+b1 \
    && rm -rf /var/lib/apt/lists/*

ENV LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0
