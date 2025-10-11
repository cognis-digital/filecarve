FROM python:3.12-slim
LABEL org.opencontainers.image.title="cognis-filecarve"
LABEL org.opencontainers.image.source="https://github.com/cognis-digital/filecarve"
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
ENTRYPOINT ["filecarve"]
