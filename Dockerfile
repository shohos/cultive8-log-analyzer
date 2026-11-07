FROM debian:bookworm-slim AS llama
RUN apt-get update && apt-get install -y --no-install-recommends git cmake g++ libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch b12183 https://github.com/ggml-org/llama.cpp /src
RUN cmake -S /src -B /src/build -DCMAKE_BUILD_TYPE=Release -DGGML_NATIVE=OFF -DGGML_CUDA=OFF -DBUILD_SHARED_LIBS=OFF -DLLAMA_OPENSSL=OFF && cmake --build /src/build --target llama-server -j2

FROM python:3.11-slim-bookworm
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 && rm -rf /var/lib/apt/lists/*
COPY --from=llama /src/build/bin/llama-server /usr/local/bin/llama-server
COPY requirements.lock.txt .
RUN python -m venv .venv && .venv/bin/pip install --no-cache-dir -r requirements.lock.txt
COPY app app
COPY scripts/run.py scripts/run.py
COPY samples samples
ENV APP_HOST=0.0.0.0
EXPOSE 8000
CMD ["python", "scripts/run.py"]
