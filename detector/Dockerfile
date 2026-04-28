FROM python:3.12-alpine

RUN apk add --no-cache iptables gcc musl-dev linux-headers

RUN addgroup -S detector && adduser -S detector -G detector

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R detector:detector /app

EXPOSE 8080

CMD ["python", "-u", "main.py"]
