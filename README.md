# zur

curl and htop had a zig baby.

A tiny TUI that hits an HTTP endpoint and shows you everything — status, timing breakdown, TLS info, response body — in one interactive screen.

![zur](https://img.shields.io/badge/built_with-zig-f7a41d?style=flat)

## Install

```
make install
```

Installs to `~/bin`. Override with `PREFIX=/usr/local/bin make install`.

Requires [Zig](https://ziglang.org/) 0.15.2+.

## Usage

```
zur https://example.com
```

```
zur -X POST -H "Content-Type: application/json" -d '{"key":"val"}' https://api.example.com
```

### Options

```
-X <method>     HTTP method (default: GET)
-H <header>     Add header (repeatable)
-d <data>       Request body (implies POST)
-k              Skip TLS verification
--no-follow     Don't follow redirects
-q              Quiet mode (exit code only)
```

### TUI

```
↑/↓  navigate
⏎    expand details / view body
r    retry (tracks min/avg/max across runs)
q    quit
```

## License

MIT
