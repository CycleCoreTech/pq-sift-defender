# Evidence directory

Sample memory images / disk images / log files used by the agent's
forensic-tool wrappers. Files are gitignored — fetch them yourself.

## Public memory image used in `samples/malware_memory_dump.json`

**M57-Patents Day 17 (Pat McGoo's workstation)**, Windows XP SP3,
~512 MB raw. Part of the M57-Patents corporate-investigation scenario
maintained by NPS Digital Corpora.

```bash
curl -L -o /tmp/m57.zip "https://digitalcorpora.s3.amazonaws.com/corpora/scenarios/2009-m57-patents/ram/pat-2009-12-05.winddramimage.zip"
unzip -p /tmp/m57.zip > evidence/pat-2009-12-05.vmem
```

The image contains a `ToolKeylogger.exe` process (PID 280, parent
`explorer.exe`), which is the canonical IOC for the scenario. The agent
should surface it when investigating `samples/malware_memory_dump.json`.

Citation: Garfinkel, S. (2009). *M57-Patents Scenario.* NPS Digital Corpora.
