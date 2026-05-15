# Sample artefacts

`report.json` is a hand-crafted example of the JSON document
`patchmgr` produces after a `patch` run on an Ubuntu 22.04 host.
Use it as a reference when integrating the tool into a SIEM or a
ticketing system.

To turn it into the matching HTML view:

```bash
patchmgr report --input samples/report.json --format html
```

The command writes `samples/report.html` next to the JSON.
