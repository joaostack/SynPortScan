# SynPortScan
Experimental project

### Parameters
```
Description:
  SynPortScan args.

Usage:
  SynPortScan [options]

Options:
  --ip <ip>            Target IP
  --gateway <gateway>  Target gateway
  --threads <threads>  Threads
  --version            Show version information
  -?, -h, --help       Show help and usage information
```
### Sample
```
dotnet run --project src -- --ip scanme.nmap.org --gateway 10.0.0.2 --threads 4
```
