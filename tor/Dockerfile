FROM alpine:3.20

# Install Tor from Alpine's package index.
# Alpine 3.20 ships Tor 0.4.8.x which supports:
#   - HiddenServiceVersion 3
#   - HiddenServiceEnableIntroDoSDefense (requires >= 0.4.2)
#   - HiddenServicePort unix: forwarding (requires >= 0.3.3.1)
RUN apk add --no-cache tor

CMD ["tor", "-f", "/etc/tor/torrc"]
