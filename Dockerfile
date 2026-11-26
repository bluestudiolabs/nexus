FROM golang:1.25-alpine AS agent
WORKDIR /src
COPY agents/windows/*.go agents/windows/go.mod ./
RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-H windowsgui -s -w' -o /NEXUS-Agent-Setup-x64.exe .
FROM python:3.13-alpine
WORKDIR /app
COPY integration_center.py features.py features.js dashboard.py dashboard.js dashboard.css server.py core.py secure.py index.html app.js extra.js agent-linux.py setup-linux.sh /app/
COPY --from=agent /NEXUS-Agent-Setup-x64.exe /app/
RUN python -m zipfile -c nexus-agent-linux.zip agent-linux.py setup-linux.sh
EXPOSE 8080
USER 65534:65534
CMD ["python", "-B", "secure.py"]
