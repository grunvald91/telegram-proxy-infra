# Telegram WEB proxy

Research target: Telegram Desktop's official proof-of-concept server:

https://github.com/telegramdesktop/tproxy-server

At the start of this project it is explicitly described upstream as a **proof-of-concept WEB proxy server for Telegram**.

Reference layout documented upstream:

```
Internet :80/:443
       -> Caddy
       -> tproxy-server on loopback
       -> official MTProxy on loopback
       -> Telegram
```

The public hostname remains a normal HTTPS website for unauthenticated visitors.

## Migration rule

Do not replace the working legacy proxy first.

Preferred sequence:
1. preserve and document legacy deployment;
2. deploy WEB proxy independently;
3. test client compatibility and reliability;
4. compare operational behavior;
5. only then decide whether to migrate or run both.
