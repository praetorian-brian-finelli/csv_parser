# csv_parser
parse nessus CSVs for the purpose of formatting for reporting templates


to run:
./csv_parser.py nessus.csv (-all) (-versions) (-print)
./csv_parser.py -help

writes to files csv_output and versions_output

-all prints all nessus findings with usable host IP tables (otherwise only prints findings that have a vkb mapped)
-versions creates a second file formatted to use with missing security patches template
-print will print all vulnerability titles from the nessus file
-help prints this message
