# tls-certificate-transparency-log-checker examples

Note: These examples (and any use of this program) will only show certs which are from CA's who have CT logs that are indexed by [crt.sh](https://crt/sh) as it's the data source.

Assuming you have installed `tls-certificate-transparency-log-checker` globally (if not, you'll need to cd to the installation directory and run the following from there, replacing `check-ct-logs` with `node ./dist/cli/check-ct-logs.js` - assuming `node` is in your $PATH):

## Find all CT logs for www.bbc.co.uk (for all time)
```
check-ct-logs -d "www.bbc.co.uk"
```

## Find all CT logs for www.bbc.co.uk (for all time) and display only the count of the "allCerts" object (no certificate details) in the JSON returned

```
check-ct-logs -d "www.bbc.co.uk" --no_by_ca --no_unexpected --no_entries
```

## Find CT logs for www.bbc.co.uk and www.bbc.com redirecting output JSON to a file
Note: This is \*nix-specific - i.e. it won't work on Winows but there's probably a powershell equivalent(?)
```
check-ct-logs -d "www.bbc.co.uk" "www.bbc.com" > out.json
```

## Find CT logs for www.bbc.co.uk & expecting GlobalSign or DigiCert certs, returning an exit code of 1 if unexpected CA's are found

You could perhaps use this on a schedule (e.g. cron) to periodically check for unexpected CA's - just check the return code of the below, 0 will indicate all is well, 1 will indicate 1 or more certificates being issued by an unexpected CA.

```
check-ct-logs -d "www.bbc.co.uk" --cas "GlobalSign.*, DigiCert.*" -e --no_all_certs --no_by_ca
```

You could perhaps then issue some sort of alert if the return code is > 0.
