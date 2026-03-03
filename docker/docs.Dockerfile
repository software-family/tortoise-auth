FROM python:3.12-slim AS builder
WORKDIR /app
COPY docs/ docs/
COPY mkdocs.yml .
RUN pip install --no-cache-dir mkdocs mkdocs-material pymdown-extensions
RUN mkdocs build

FROM nginx:alpine
COPY --from=builder /app/site /usr/share/nginx/html
EXPOSE 80