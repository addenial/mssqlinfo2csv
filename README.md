# mssql-info-parser.py
Script to convert nmap ms-sql-info XML output to a CSV file

Currently the script pulls and parses the following fields of interest:

`IP,DNS,Server,Instance,TCP,Named Pipe`

Fields details~
IP Address,
DNS Hostname,
Windows Server Name,
SQL Server Instance,
Instance TCP Port,
Instance Named Pipe

## Usage
`python ./mssql-info-parser.py <results-ms-sql-info.xml> `

## Examples
Parse and output to file:

`python ./mssql-info-parser.py results-ms-sql-info.xml > parsed-mssql.csv `

View only IP and TCP port of the available mssql database instances:

`cat parsed-mssql.csv | cut -d, -f1,5  `

Command to reorder column view in Linux-
(Server,IP,TCP,Instance,Named Pipe,DNS)

` sed 's/\r//' parsed-mssql.csv | awk -F, '{print $3,$1,$5,$4,$6,$2}' OFS=, `

Linux command to sort (but keeping the first header row unchanged)

` sed 's/\r//' parsed-mssql.csv | awk -F, '{print $3,$1,$5,$4,$6,$2}' OFS=, | (read -r; printf "%s\n" "$REPLY"; sort)   `
