# csv_parser
parse nessus CSVs for the purpose of formatting for reporting templates


to run:
./csv_parser.py nessus.csv (-all) (-versions) (-print)
./csv_parser.py -help

  -all prints all nessus findings with usable host IP tables (otherwise only prints findings that have a vkb mapped)
  -versions creates a second file formatted to use with missing security patches template
  -print will print all vulnerability titles from the nessus file to the screen
  -help prints this message

writes to files csv_output and versions_output


csv_output takes the form:

% BeginTable(targets) %
columns: 3
generic_hosts:
 - 10.10.1.1 443/udp
 - 10.10.1.2 443/tcp
% EndTable(targets) %


versions_output takes the form:

% BeginTable(targets) %
columns: 3
hosts_with_header:
 - header:
   - name: Apache 2.2.x
   - hosts:
     - 10.10.1.1 443/udp
 - header:
   - name: PHP 5.4.x
   - hosts:
     - 10.10.1.2 443/tcp
% EndTable(targets) %
