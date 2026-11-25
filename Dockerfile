# vilauncher-builder: builds VIctory and XCL trees for Windows from Linux (cargo-xwin) and
# publishes them for VILauncher. Railway runs it as a cron job (railway.json).
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends procps \
      ca-certificates curl git python3 zstd clang lld llvm build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

# The projects' code is compiled by this user, never by root, and without the service's
# secrets in its environment (build.py, run_as_builder).
RUN useradd --create-home --shell /bin/sh build
USER build
WORKDIR /home/build
ENV PATH=/app/builder/bin:/home/build/.cargo/bin:/usr/local/bin:/usr/bin:/bin
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && rustup target add x86_64-pc-windows-msvc \
    && cargo install --locked cargo-xwin --version 0.24.1

COPY --chown=build:build builder/bin/clang-cl /app/builder/bin/clang-cl
# Downloads the MSVC CRT and Windows SDK headers and libraries into the image (accepting
# Microsoft's license for them), so a run does not fetch them again.
RUN cargo new -q --bin warm && cd warm \
    && cargo xwin build --release --target x86_64-pc-windows-msvc \
    && test -f target/x86_64-pc-windows-msvc/release/warm.exe \
    && cd .. && rm -rf warm

USER root
# opus.dll for xcl: MSYS2's UCRT64 build (imports only KERNEL32 and the UCRT, which Proton and
# Wine provide), pinned by version and SHA-256.
ARG OPUS_PKG=mingw-w64-ucrt-x86_64-opus-1.6.1-2-any.pkg.tar.zst
ARG OPUS_SHA256=bb114bcf26225f50f874497ebfd6b8224fff2a20bda3f8ee45cd07ce5f02657b
RUN mkdir -p /opt/opus/bin /tmp/opus && cd /tmp/opus \
    && curl -fsSL -o pkg.tar.zst "https://repo.msys2.org/mingw/ucrt64/${OPUS_PKG}" \
    && echo "${OPUS_SHA256}  pkg.tar.zst" | sha256sum -c - \
    && tar --zstd -xf pkg.tar.zst ucrt64/bin/libopus-0.dll ucrt64/share/licenses/opus/COPYING \
    && cp ucrt64/bin/libopus-0.dll /opt/opus/bin/opus.dll \
    && cp ucrt64/share/licenses/opus/COPYING /opt/opus/COPYING \
    && rm -rf /tmp/opus

COPY builder /app/builder
RUN chmod 755 /app/builder/bin/clang-cl && mkdir -p /work && chown build:build /work
ENV WORK_DIR=/work
CMD ["python3", "-I", "/app/builder/build.py"]
