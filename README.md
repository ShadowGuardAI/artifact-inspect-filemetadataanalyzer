# artifact-inspect-FileMetadataAnalyzer
Analyzes file metadata (creation date, modification date, owner, permissions, etc.) and flags anomalies based on heuristic rules or user-defined thresholds. Uses `os` and `stat` modules. - Focused on Analyzes file artifacts (e.g., executables, documents) to identify potential security risks, suspicious patterns, and embedded threats by extracting metadata and performing static analysis. Focuses on identifying characteristics indicative of malware or malicious code.

## Install
`git clone https://github.com/ShadowGuardAI/artifact-inspect-filemetadataanalyzer`

## Usage
`./artifact-inspect-filemetadataanalyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-t`: Threshold in days for flagging old modification/creation dates. Defaults to 30 days.
- `-o`: Expected owner of the file. Flags if different.
- `-p`: Expected permissions (e.g., 
- `--pe_check`: Perform additional checks if the file is a PE executable.

## License
Copyright (c) ShadowGuardAI
