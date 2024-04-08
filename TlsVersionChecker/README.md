# TLS Version Checker

TLS Version Checker is a simple command-line tool written in C# to check the SSL/TLS protocol version and cipher suite used by a .NET application when connecting to a specific host.

## Usage
TlsVersionChecker.exe <target_host> [--use tls13|tls12|tls11|tls]

### Options

- `--help`: Show help message
- `--use-tls-Version VERSION`: Force the use of a specific TLS version (e.g., tls13, tls12, tls11, tls, system)

## Requirements

The latest version of [.NET SDK](https://dotnet.microsoft.com/download/dotnet).


## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.